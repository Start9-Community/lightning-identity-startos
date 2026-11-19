package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/guard"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/macaroon"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// TestSendingEndToEnd proves milestone 2's properties against the fake LND:
// no spend credential without the latch; the credential carries the custom
// caveat; a payment within caps succeeds and is ledgered on both sides; the
// guard — not core — refuses an over-cap payment and the 24-hour window; a
// core that ignores its own budget is still capped; a connection budget is
// refused by core; disabling drops the credential.
func TestSendingEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	guard.AuthPoll = 200 * time.Millisecond
	dir := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "li")
	defer os.RemoveAll(sockDir)
	lndFake := newFakeLND(t, dir)
	grpcFake := lndFake.startGRPC(t, lndFake.leaf)
	me := uint32(os.Getuid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	credDir := filepath.Join(dir, "credentials")
	guardDir := filepath.Join(dir, "guard")
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	g, err := guard.New(guard.Config{
		LNDRestURL: lndFake.srv.URL, LNDGRPCAddress: grpcFake.addr, LNDCAFile: lndFake.caFile, AdminMacaroon: lndFake.adminMacaroonFile(t, dir),
		CredentialsDir: credDir, StateDir: guardDir, SocketPath: filepath.Join(sockDir, "g.sock"),
		AllowedUIDs: []uint32{me}, IPRange: cidr, Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	go g.Run(ctx)
	waitFor(t, "receive credential", 10*time.Second, func() bool {
		st, err := os.Stat(filepath.Join(credDir, "recv.macaroon"))
		return err == nil && st.Size() > 0
	})
	waitFor(t, "middleware registered", 10*time.Second, func() bool { return grpcFake.registered() == guard.MiddlewareName })

	// ---- core ----
	svc, err := core.New(core.Config{
		DataDir: filepath.Join(dir, "core"), CredentialsDir: credDir, IdentitiesDir: filepath.Join(dir, "identities"),
		GuardSocket: filepath.Join(sockDir, "g.sock"), EdgeSocket: filepath.Join(sockDir, "e.sock"), EdgeUIDs: []uint32{me},
		LNDRestURL: lndFake.srv.URL, LNDCAFile: lndFake.caFile, BaseURL: "https://pay.example", RelayURL: "wss://pay.example/relay",
		Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	n := nwc.New(svc, logger)
	alice, err := svc.NewIdentity("alice", "Alice", "", false, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// Calling NWC's dispatcher directly keeps this test about money, not
	// relays; the relay path is proven in TestEndToEnd.
	conn := &store.Connection{ID: "c-pay", IdentityID: alice.ID, Label: "payer", ClientPubkey: strings.Repeat("11", 32), Methods: nwc.AllMethods(), CreatedAt: time.Now()}
	if err := svc.Store().PutConnection(conn); err != nil {
		t.Fatal(err)
	}
	call := func(method string, params any) (string, string) {
		t.Helper()
		raw, _ := json.Marshal(params)
		res := n.DispatchForTest(ctx, alice, conn, method, raw)
		var out struct {
			Error *struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(res, &out)
		if out.Error != nil {
			return out.Error.Code, out.Error.Message
		}
		return "", string(res)
	}

	// 1. No latch, no credential, pay_invoice is RESTRICTED.
	if _, err := os.Stat(filepath.Join(credDir, "spend.macaroon")); err == nil {
		t.Fatal("spend credential must not exist before authorization")
	}
	if code, _ := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(10_000_000, false)}); code != nwc.ErrRestricted {
		t.Fatalf("expected RESTRICTED before authorization, got %q", code)
	}

	// 2. The ceremony: the package action writes the authorization file.
	writeAuth := func(enabled bool, maxPay, max24 int64) {
		a := guard.Authorization{ID: nostr.GeneratePrivateKey()[:16], CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Enabled: enabled, MaxPaymentMsat: maxPay, Max24hMsat: max24}
		raw, _ := json.Marshal(a)
		if err := os.WriteFile(filepath.Join(guardDir, "authorization.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeAuth(true, 60_000_000, 120_000_000) // 60k sats per payment, 120k sats per day
	waitFor(t, "spend credential", 15*time.Second, func() bool {
		st, err := os.Stat(filepath.Join(credDir, "spend.macaroon"))
		return err == nil && st.Size() > 0
	})
	raw, _ := os.ReadFile(filepath.Join(credDir, "spend.macaroon"))
	caveats, _ := macaroon.Caveats(hexOf(raw))
	found := false
	for _, c := range caveats {
		if strings.HasPrefix(c, "lnd-custom "+guard.MiddlewareName+" ") {
			found = true
		}
	}
	if !found || len(caveats) != 3 {
		t.Fatalf("spend credential caveats: %v", caveats)
	}
	if !svc.SendingEnabled() {
		t.Fatal("core should see sending enabled")
	}

	// 3. Sending is on, but alice is a fresh wallet with nothing in it: her
	// own balance refuses before the guard is ever consulted.
	if code, msg := call("get_balance", map[string]any{}); code != "" || !strings.Contains(msg, `"balance":0`) {
		t.Fatalf("fresh identity balance: %s %s", code, msg)
	}
	if code, msg := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(10_000_000, false)}); code != nwc.ErrInsufficient || strings.Contains(msg, "guard:") {
		t.Fatalf("expected INSUFFICIENT_BALANCE on an empty identity, got %s %q", code, msg)
	}
	// An operator credit of 200k sats is bookkeeping, not a node movement.
	if _, err := svc.Adjust(alice, 200_000_000, "opening balance"); err != nil {
		t.Fatal(err)
	}
	if code, msg := call("get_balance", map[string]any{}); code != "" || !strings.Contains(msg, `"balance":200000000`) {
		t.Fatalf("credited balance: %s %s", code, msg)
	}
	// The credit shows in the history as a settled incoming entry with no
	// invoice (what an LNbits top-up looks like), so the list sums to the
	// balance. `type: outgoing` leaves it out; `unpaid` adds unpaid invoices
	// to the list (NWC-05) and takes nothing away, so the credit stays.
	if code, msg := call("list_transactions", map[string]any{}); code != "" || !strings.Contains(msg, `"description":"opening balance"`) || !strings.Contains(msg, `"amount":200000000`) || strings.Contains(msg, `"invoice"`) {
		t.Fatalf("credit in list_transactions: %s %s", code, msg)
	}
	if _, msg := call("list_transactions", map[string]any{"type": "outgoing"}); strings.Contains(msg, "opening balance") {
		t.Fatalf("credit listed as outgoing: %s", msg)
	}
	if _, msg := call("list_transactions", map[string]any{"unpaid": true}); !strings.Contains(msg, "opening balance") {
		t.Fatalf("credit missing when unpaid invoices are included: %s", msg)
	}

	// A payment within caps succeeds and both ledgers agree.
	code, body := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(10_000_000, false)})
	if code != "" || !strings.Contains(body, `"preimage"`) {
		t.Fatalf("pay_invoice: %s %s", code, body)
	}
	pays, _ := svc.Store().ListPayments(alice.ID, 0, 10)
	if len(pays) != 1 || pays[0].State != store.PaymentSettled || pays[0].FeeMsat != 1000 {
		t.Fatalf("payment ledger: %+v", pays)
	}
	// The balance dropped by amount + actual fee, not the fee reserve.
	if b, _ := svc.Balance(alice.ID); b.Available != 200_000_000-10_001_000 || b.InFlight != 0 {
		t.Fatalf("balance after payment: %+v", b)
	}
	gs, _ := svc.GuardStatus(ctx)
	if spent, _ := gs["spent_24h_msat"].(float64); int64(spent) != 10_001_000 {
		t.Fatalf("guard ledger: spent_24h_msat = %v", gs["spent_24h_msat"])
	}

	// 4. Over the per-payment cap (alice has plenty): refused by the guard, not core (no
	// connection budget is set, so core has nothing to refuse with).
	code, msg := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(70_000_000, false)})
	if code != nwc.ErrQuota || !strings.Contains(msg, "guard:") || !strings.Contains(msg, "per-payment cap") {
		t.Fatalf("expected guard per-payment refusal, got %s %q", code, msg)
	}

	// 5. The 24-hour window: 10.001k used; 55k ok (65.552k); 55k would reach
	// 121.1k > 120k and is refused by the guard.
	if code, msg := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(55_000_000, false)}); code != "" {
		t.Fatalf("second payment should pass: %s %q", code, msg)
	}
	code, msg = call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(55_000_000, false)})
	if code != nwc.ErrQuota || !strings.Contains(msg, "24-hour cap") {
		t.Fatalf("expected guard 24h refusal, got %s %q", code, msg)
	}
	// A failed payment releases its reservation instead of consuming budget.
	if code, msg := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(20_000_000, true)}); code != "PAYMENT_FAILED" {
		t.Fatalf("expected PAYMENT_FAILED, got %s %q", code, msg)
	}
	gs, _ = svc.GuardStatus(ctx)
	if reserved, _ := gs["reserved_msat"].(float64); reserved != 0 {
		t.Fatalf("failed payment left a reservation: %v", reserved)
	}

	// 6. A core that ignores its own limits: drive LND's REST directly with
	// the spend credential, as a compromised core would, for an amount the
	// 24-hour window cannot absorb. The guard refuses it.
	direct, err := lnd.New(lndFake.srv.URL, lndFake.caFile, filepath.Join(credDir, "spend.macaroon"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = direct.SendPaymentV2(ctx, lnd.SendPaymentRequest{PaymentRequest: makeFakeInvoice(55_000_000, false), FeeLimitMsat: 1000, TimeoutSeconds: 10})
	if err == nil || !strings.Contains(err.Error(), "guard:") {
		t.Fatalf("direct over-window payment should be refused by the guard, got %v", err)
	}
	// ...and a method the credential names but the guard has no pricer
	// for would also be refused; DecodePayReq is on the read-only list and
	// passes, which is the only reason core can price before paying.
	if _, err := direct.DecodePayReq(ctx, makeFakeInvoice(1000, false)); err != nil {
		t.Fatalf("DecodePayReq under the spend credential: %v", err)
	}

	// 7. A connection budget is core's own refusal, before the guard.
	budgeted := &store.Connection{ID: "c-small", IdentityID: alice.ID, Label: "small", ClientPubkey: strings.Repeat("22", 32), Methods: nwc.AllMethods(), BudgetMsat: 5_000_000, BudgetPeriod: store.PeriodDaily, CreatedAt: time.Now()}
	_ = svc.Store().PutConnection(budgeted)
	rawp, _ := json.Marshal(map[string]any{"invoice": makeFakeInvoice(10_000_000, false)})
	res := n.DispatchForTest(ctx, alice, budgeted, "pay_invoice", rawp)
	if !strings.Contains(string(res), nwc.ErrQuota) || strings.Contains(string(res), "guard:") {
		t.Fatalf("expected core budget refusal, got %s", res)
	}
	// get_balance is the identity's balance even on a budgeted connection:
	// the budget limits spending, it never hides what is there.
	b, _ := svc.Balance(alice.ID)
	res = n.DispatchForTest(ctx, alice, budgeted, "get_balance", []byte(`{}`))
	if b.Available <= 5_000_000 || !strings.Contains(string(res), fmt.Sprintf(`"balance":%d`, b.Available)) {
		t.Fatalf("get_balance: %s (ledger %+v)", res, b)
	}
	// A debit below what a payment needs is refused as INSUFFICIENT_BALANCE
	// with the ledger, not the guard, as the reason.
	if _, err := svc.Adjust(alice, -(b.Available - 500_000), "drain for test"); err != nil {
		t.Fatal(err)
	}
	if code, msg := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(1_000_000, false)}); code != nwc.ErrInsufficient || strings.Contains(msg, "guard:") {
		t.Fatalf("expected INSUFFICIENT_BALANCE after debit, got %s %q", code, msg)
	}
	if _, err := svc.Adjust(alice, 100_000_000, "refill"); err != nil {
		t.Fatal(err)
	}

	// 7b. Self-pay: bob is a second identity on the same node. An invoice bob
	// made is one of this node's own, so Lightning cannot carry it; with
	// self-pay on it settles in the ledger — alice debited, bob credited,
	// bob's invoice settled with the real preimage, the LND invoice
	// cancelled, no fee, nothing through the guard. With self-pay off it is
	// refused up front instead of failing with "no route".
	bob, err := svc.NewIdentity("bob", "Bob", "", false, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	bobConn := &store.Connection{ID: "c-bob", IdentityID: bob.ID, Label: "bob app", ClientPubkey: strings.Repeat("33", 32), Methods: nwc.AllMethods(), CreatedAt: time.Now()}
	_ = svc.Store().PutConnection(bobConn)
	rawmi, _ := json.Marshal(map[string]any{"amount": 2_000_000, "description": "from alice"})
	res = n.DispatchForTest(ctx, bob, bobConn, "make_invoice", rawmi)
	var mi struct {
		Result struct {
			Invoice     string `json:"invoice"`
			PaymentHash string `json:"payment_hash"`
		} `json:"result"`
	}
	_ = json.Unmarshal(res, &mi)
	if mi.Result.Invoice == "" {
		t.Fatalf("make_invoice for bob: %s", res)
	}
	st := svc.Settings()
	st.SelfPay = false
	if err := svc.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
	if code, msg := call("pay_invoice", map[string]any{"invoice": mi.Result.Invoice}); code != nwc.ErrOther || !strings.Contains(msg, "self-pay") {
		t.Fatalf("expected a self-pay refusal with self-pay off, got %s %q", code, msg)
	}
	st.SelfPay = true
	_ = svc.UpdateSettings(st)
	before, _ := svc.Balance(alice.ID)
	gsBefore, _ := svc.GuardStatus(ctx)
	code, body = call("pay_invoice", map[string]any{"invoice": mi.Result.Invoice})
	if code != "" || !strings.Contains(body, `"preimage"`) || !strings.Contains(body, `"fees_paid":0`) {
		t.Fatalf("self-pay: %s %s", code, body)
	}
	after, _ := svc.Balance(alice.ID)
	if before.Available-after.Available != 2_000_000 {
		t.Fatalf("alice debited %d, want 2000000", before.Available-after.Available)
	}
	if bb, _ := svc.Balance(bob.ID); bb.Available != 2_000_000 || bb.Received != 2_000_000 {
		t.Fatalf("bob credited: %+v", bb)
	}
	bobInv, _ := svc.Store().GetInvoice(mi.Result.PaymentHash)
	if bobInv.State != store.InvoiceSettled || len(bobInv.PreimageEnc) == 0 || svc.Preimage(bobInv.PreimageEnc) == "" {
		t.Fatalf("bob's invoice not settled with a preimage: %+v", bobInv)
	}
	lndFake.mu.Lock()
	canceled := lndFake.invoices[mi.Result.PaymentHash].Canceled
	lndFake.mu.Unlock()
	if !canceled {
		t.Fatal("the LND invoice was not cancelled")
	}
	gsAfter, _ := svc.GuardStatus(ctx)
	if gsAfter["spent_24h_msat"] != gsBefore["spent_24h_msat"] {
		t.Fatalf("self-pay must not touch the guard's window: %v -> %v", gsBefore["spent_24h_msat"], gsAfter["spent_24h_msat"])
	}
	// Paying it again is refused: the ledger knows it is settled.
	if code, msg := call("pay_invoice", map[string]any{"invoice": mi.Result.Invoice}); code == "" || !strings.Contains(msg, "already") {
		t.Fatalf("expected refusal of a settled own invoice, got %s %q", code, msg)
	}
	// The internal transaction shows in both histories with the flag.
	if _, msg := call("list_transactions", map[string]any{"type": "outgoing"}); !strings.Contains(msg, `"internal":true`) {
		t.Fatalf("alice's history lacks the internal marker: %s", msg)
	}

	// 8. Lowering caps over the socket works; raising is refused.
	if _, err := svc.LowerCaps(ctx, 70_000_000, 120_000_000); err == nil {
		t.Fatal("raising the per-payment cap over the socket must be refused")
	}
	if _, err := svc.LowerCaps(ctx, 30_000_000, 100_000_000); err != nil {
		t.Fatalf("lowering caps: %v", err)
	}

	// 9. Disable: the credential disappears and payments are RESTRICTED.
	if _, err := svc.DisableSending(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "spend credential removed", 5*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(credDir, "spend.macaroon"))
		return err != nil
	})
	if code, _ := call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(1_000_000, false)}); code != nwc.ErrRestricted {
		t.Fatalf("expected RESTRICTED after disable, got %q", code)
	}
	// Even the old credential, if kept by a compromised core, is dead: the
	// guard's latch is off.
	_, err = direct.SendPaymentV2(ctx, lnd.SendPaymentRequest{PaymentRequest: makeFakeInvoice(1_000_000, false), FeeLimitMsat: 1000, TimeoutSeconds: 10})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("stale credential after disable should be refused by the guard, got %v", err)
	}
	// Re-enabling bakes a credential under a new nonce; the stale one stays dead.
	writeAuth(true, 60_000_000, 120_000_000)
	waitFor(t, "spend credential re-baked", 15*time.Second, func() bool {
		st, err := os.Stat(filepath.Join(credDir, "spend.macaroon"))
		return err == nil && st.Size() > 0
	})
	_, err = direct.SendPaymentV2(ctx, lnd.SendPaymentRequest{PaymentRequest: makeFakeInvoice(1_000_000, false), FeeLimitMsat: 1000, TimeoutSeconds: 10})
	if err == nil || !strings.Contains(err.Error(), "current sending authorization") {
		t.Fatalf("credential from the previous authorization should be refused, got %v", err)
	}
}

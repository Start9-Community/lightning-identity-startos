package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
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
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// sendingRig is guard + core + NWC against the fake LND with sending
// authorized, for tests about money rather than transport.
type sendingRig struct {
	ctx   context.Context
	svc   *core.Service
	nwc   *nwc.Service
	lnd   *fakeLND
	grpc  *fakeGRPC
	alice *store.Identity
	conn  *store.Connection
}

func newSendingRig(t *testing.T, maxPayMsat, max24hMsat int64) *sendingRig {
	t.Helper()
	guard.AuthPoll = 200 * time.Millisecond
	dir := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "li")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	lndFake := newFakeLND(t, dir)
	grpcFake := lndFake.startGRPC(t, lndFake.leaf)
	me := uint32(os.Getuid())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	credDir, guardDir := filepath.Join(dir, "credentials"), filepath.Join(dir, "guard")
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	g, err := guard.New(guard.Config{
		LNDRestURL: lndFake.srv.URL, LNDGRPCAddress: grpcFake.addr, LNDCAFile: lndFake.caFile, AdminMacaroon: lndFake.adminMacaroonFile(t, dir),
		CredentialsDir: credDir, StateDir: guardDir, SocketPath: filepath.Join(sockDir, "g.sock"),
		AllowedUIDs: []uint32{me}, IPRange: cidr, Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	guardDone := make(chan struct{})
	go func() { _ = g.Run(ctx); close(guardDone) }()
	// Registered after TempDir, so it runs before the directory is removed:
	// the guard must be done writing its state by then.
	t.Cleanup(func() {
		cancel()
		select {
		case <-guardDone:
		case <-time.After(3 * time.Second):
		}
		time.Sleep(50 * time.Millisecond)
	})
	waitFor(t, "middleware registered", 10*time.Second, func() bool { return grpcFake.registered() == guard.MiddlewareName })
	svc, err := core.New(core.Config{
		DataDir: filepath.Join(dir, "core"), CredentialsDir: credDir, IdentitiesDir: filepath.Join(dir, "identities"),
		GuardSocket: filepath.Join(sockDir, "g.sock"), EdgeSocket: filepath.Join(sockDir, "e.sock"), EdgeUIDs: []uint32{me},
		LNDRestURL: lndFake.srv.URL, LNDCAFile: lndFake.caFile, BaseURL: "https://pay.example", RelayURL: "wss://pay.example/relay",
		Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	n := nwc.New(svc, logger)
	alice, err := svc.NewIdentity("alice", "Alice", "", false, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	conn := &store.Connection{ID: "c-pay", IdentityID: alice.ID, Label: "payer", ClientPubkey: strings.Repeat("11", 32), Methods: nwc.AllMethods(), CreatedAt: time.Now()}
	if err := svc.Store().PutConnection(conn); err != nil {
		t.Fatal(err)
	}
	a := guard.Authorization{ID: nostr.GeneratePrivateKey()[:16], CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Enabled: true, MaxPaymentMsat: maxPayMsat, Max24hMsat: max24hMsat}
	raw, _ := json.Marshal(a)
	_ = os.MkdirAll(guardDir, 0o750)
	if err := os.WriteFile(filepath.Join(guardDir, "authorization.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "spend credential", 15*time.Second, func() bool {
		st, err := os.Stat(filepath.Join(credDir, "spend.macaroon"))
		return err == nil && st.Size() > 0
	})
	return &sendingRig{ctx: ctx, svc: svc, nwc: n, lnd: lndFake, grpc: grpcFake, alice: alice, conn: conn}
}

// call runs one NWC method for alice and returns (error code, message or body).
func (r *sendingRig) call(method string, params any) (string, string) {
	raw, _ := json.Marshal(params)
	res := r.nwc.DispatchForTest(r.ctx, r.alice, r.conn, method, raw)
	var out struct {
		Error *struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(res, &out)
	if out.Error != nil {
		return out.Error.Code, out.Error.Message
	}
	return "", string(res)
}

// TestHoldInvoiceCannotFreeBalance is the accounting attack a multi-user
// Lightning service has to survive. The payer controls the recipient, which
// accepts the HTLC and holds it. The wallet's request times out long before
// the payment resolves. If that timeout is booked as a failure, the identity
// gets its balance back while the payment is still in flight on the node —
// and the recipient settles it afterwards: the identity has spent the same
// sats twice, out of the node's other funds. The payment must instead stay
// pending, holding the balance, until LND itself says how it ended.
func TestHoldInvoiceCannotFreeBalance(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 500_000_000)
	old := core.SendWait
	core.SendWait = 400 * time.Millisecond
	defer func() { core.SendWait = old }()
	if _, err := r.svc.Adjust(r.alice, 50_000_000, "opening balance"); err != nil {
		t.Fatal(err)
	}

	// 1. Pay a hold invoice for 40k sats of alice's 50k. The wait runs out.
	hold := makeHoldInvoice(40_000_000)
	holdHash := strings.Split(hold, "x")[2]
	code, msg := r.call("pay_invoice", map[string]any{"invoice": hold})
	if code == "" {
		t.Fatalf("a held payment cannot report success: %s", msg)
	}
	p, err := r.svc.Store().GetPayment(holdHash)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != store.PaymentPending {
		t.Fatalf("a payment still in flight on the node was booked as %q (%s): its balance is free to spend again", p.State, p.FailureReason)
	}
	bal, _ := r.svc.Balance(r.alice.ID)
	if bal.InFlight != 40_400_000 || bal.Available != 9_600_000 {
		t.Fatalf("balance must stay held while in flight: %+v", bal)
	}

	// The guard heard the stream end in an error (the caller hung up). That
	// is not a verdict either: its window must keep the payment reserved.
	waitFor(t, "guard keeps the reservation", 5*time.Second, func() bool {
		gs, _ := r.svc.GuardStatus(r.ctx)
		reserved, _ := gs["reserved_msat"].(float64)
		return int64(reserved) == 40_400_000
	})

	// 2. The second spend of the same sats is refused by the ledger.
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(40_000_000, false)}); code != nwc.ErrInsufficient {
		t.Fatalf("double spend not refused: %s %q", code, msg)
	}
	// ...and a retry of the held invoice is refused too, not sent twice.
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": hold}); code == "" || !strings.Contains(msg, "already") {
		t.Fatalf("retry of an in-flight payment: %s %q", code, msg)
	}

	// 3. Reconciling while it is still held changes nothing.
	r.svc.ReconcilePaymentsOnce(r.ctx)
	if p, _ := r.svc.Store().GetPayment(holdHash); p.State != store.PaymentPending {
		t.Fatalf("reconcile resolved an in-flight payment as %q", p.State)
	}

	// 4. The recipient settles. The ledger follows LND: settled, real fee.
	r.grpc.release(holdHash, true)
	r.svc.ReconcilePaymentsOnce(r.ctx)
	p, _ = r.svc.Store().GetPayment(holdHash)
	if p.State != store.PaymentSettled || p.FeeMsat != 1000 || r.svc.Preimage(p.PreimageEnc) == "" {
		t.Fatalf("settled hold payment not booked: %+v", p)
	}
	bal, _ = r.svc.Balance(r.alice.ID)
	if bal.Available != 50_000_000-40_001_000 || bal.InFlight != 0 {
		t.Fatalf("balance after settlement: %+v", bal)
	}
	gs, _ := r.svc.GuardStatus(r.ctx)
	if spent, _ := gs["spent_24h_msat"].(float64); int64(spent) != 40_001_000 {
		t.Fatalf("guard window after settlement: spent_24h_msat=%v reserved_msat=%v", gs["spent_24h_msat"], gs["reserved_msat"])
	}

	// 5. A held payment the recipient lets fail gives the balance back, but
	// only once LND says so.
	hold2 := makeHoldInvoice(5_000_000)
	hash2 := strings.Split(hold2, "x")[2]
	r.call("pay_invoice", map[string]any{"invoice": hold2})
	if p, _ := r.svc.Store().GetPayment(hash2); p.State != store.PaymentPending {
		t.Fatalf("second held payment: %q", p.State)
	}
	r.grpc.release(hash2, false)
	r.svc.ReconcilePaymentsOnce(r.ctx)
	if p, _ := r.svc.Store().GetPayment(hash2); p.State != store.PaymentFailed {
		t.Fatalf("failed hold payment not released: %q", p.State)
	}
	if bal, _ := r.svc.Balance(r.alice.ID); bal.Available != 50_000_000-40_001_000 {
		t.Fatalf("balance after a failed hold: %+v", bal)
	}

	// 6. An invoice this node already paid by other means (Zeus, say) is
	// refused by LND before anything starts; the old payment must not be
	// mistaken for ours and debited.
	already := makeFakeInvoice(1_000_000, false)
	alreadyHash := strings.Split(already, "x")[2]
	r.grpc.mu.Lock()
	r.grpc.payments[alreadyHash] = &fakePayment{Hash: alreadyHash, Preimage: strings.Repeat("ab", 32), Msat: 1_000_000, FeeMsat: 0, Status: "SUCCEEDED", Created: time.Now().Add(-time.Hour)}
	r.grpc.mu.Unlock()
	before, _ := r.svc.Balance(r.alice.ID)
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": already}); code == "" {
		t.Fatalf("paying an already-paid invoice reported success: %s", msg)
	}
	if p, _ := r.svc.Store().GetPayment(alreadyHash); p.State != store.PaymentFailed {
		t.Fatalf("already-paid invoice booked as %q", p.State)
	}
	if after, _ := r.svc.Balance(r.alice.ID); after != before {
		t.Fatalf("already-paid invoice changed the balance: %+v -> %+v", before, after)
	}
	// ...and the guard, which reserved it and then heard an error, looked it
	// up, saw LND's record predates the request, and let the window go.
	waitFor(t, "guard releases the refused request", 5*time.Second, func() bool {
		gs, _ := r.svc.GuardStatus(r.ctx)
		reserved, _ := gs["reserved_msat"].(float64)
		spent, _ := gs["spent_24h_msat"].(float64)
		return reserved == 0 && int64(spent) == 40_001_000
	})
}

// TestGuardCapsSurviveOverflow drives LND directly with the spend credential,
// as a compromised core would, using a fee limit chosen so that amount +
// fee limit wraps around int64. The guard's caps are the hard layer: they
// must hold against arithmetic tricks, not only against honest requests.
func TestGuardCapsSurviveOverflow(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 120_000_000) // 60k sats per payment, 120k per day
	direct, err := lnd.New(r.lnd.srv.URL, r.lnd.caFile, filepath.Join(r.svc.Config().CredentialsDir, "spend.macaroon"))
	if err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]lnd.SendPaymentRequest{
		"fee limit wraps the sum negative": {PaymentRequest: makeFakeInvoice(5_000_000_000, false), FeeLimitMsat: lnd.Int64(math.MaxInt64 - 1_000_000_000), TimeoutSeconds: 10},
		"negative fee limit":               {PaymentRequest: makeFakeInvoice(100_000_000, false), FeeLimitMsat: lnd.Int64(-90_000_000), TimeoutSeconds: 10},
		"amountless amount wraps":          {PaymentRequest: makeFakeInvoice(0, false), AmtMsat: lnd.Int64(math.MaxInt64 - 5), FeeLimitMsat: 1000, TimeoutSeconds: 10},
	} {
		res, err := direct.SendPaymentV2(r.ctx, req)
		if err == nil || !strings.Contains(err.Error(), "guard:") {
			t.Errorf("%s: the guard let it through: res=%+v err=%v", name, res, err)
		}
	}
	gs, _ := r.svc.GuardStatus(r.ctx)
	if spent, _ := gs["spent_24h_msat"].(float64); spent != 0 {
		t.Errorf("guard window after refused requests: spent_24h_msat=%v", gs["spent_24h_msat"])
	}
	if reserved, _ := gs["reserved_msat"].(float64); reserved != 0 {
		t.Errorf("guard window after refused requests: reserved_msat=%v", gs["reserved_msat"])
	}
}

// TestFeeLimitSetting covers the small-zap failure seen on a real node: a
// 3-sat payment got a fee limit of 1 sat (1 %, floor 1 sat), LND found no
// route that cheap, and the wallet saw the zap fail. The limit is now an
// operator setting with a floor that buys a few hops.
func TestFeeLimitSetting(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 500_000_000)
	if _, err := r.svc.Adjust(r.alice, 100_000, "opening balance"); err != nil {
		t.Fatal(err)
	}
	limitOf := func(inv string) int64 {
		t.Helper()
		p, err := r.svc.Store().GetPayment(strings.Split(inv, "x")[2])
		if err != nil {
			t.Fatal(err)
		}
		return p.FeeLimitMsat
	}

	// Default: a 3-sat zap may spend up to 10 sats on routing.
	zap := makeFakeInvoice(3_000, false)
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": zap}); code != "" {
		t.Fatalf("3-sat zap: %s %q", code, msg)
	}
	if got := limitOf(zap); got != core.DefaultFeeLimitMinMsat {
		t.Fatalf("3-sat zap went out with a fee limit of %d msat, want the %d floor", got, core.DefaultFeeLimitMinMsat)
	}
	// Only the real fee (1 sat in the fake) is charged, not the limit.
	if bal, _ := r.svc.Balance(r.alice.ID); bal.Sent != 4_000 || bal.InFlight != 0 || bal.Available != 96_000 {
		t.Fatalf("after a 3-sat zap with a 1-sat fee: %+v", bal)
	}

	// The operator's setting applies to the next payment, no restart.
	st := r.svc.Settings()
	st.FeeLimitPPM, st.FeeLimitMinMsat = 50_000, 2_000
	if err := r.svc.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
	small, big := makeFakeInvoice(3_000, false), makeFakeInvoice(80_000, false)
	for _, inv := range []string{small, big} {
		if code, msg := r.call("pay_invoice", map[string]any{"invoice": inv}); code != "" {
			t.Fatalf("pay after settings change: %s %q", code, msg)
		}
	}
	if got := limitOf(small); got != 2_000 {
		t.Fatalf("floor after change: %d, want 2000", got)
	}
	if got := limitOf(big); got != 4_000 {
		t.Fatalf("5%% of 80 sats: %d, want 4000", got)
	}

	// The limit is part of what a payment needs: 11 sats left, a 10-sat
	// payment with a 2-sat floor does not fit, a 9-sat one does.
	if bal, _ := r.svc.Balance(r.alice.ID); bal.Available != 11_000 {
		t.Fatalf("balance before the edge case: %+v", bal)
	}
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(10_000, false)}); code != nwc.ErrInsufficient {
		t.Fatalf("amount + fee limit over the balance: %s %q", code, msg)
	}
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(9_000, false)}); code != "" {
		t.Fatalf("amount + fee limit within the balance: %s %q", code, msg)
	}

	// Nonsense is refused.
	for name, bad := range map[string]store.Settings{
		"both zero":        {InvoiceExpirySeconds: 600},
		"over 10 percent":  {InvoiceExpirySeconds: 600, FeeLimitPPM: core.MaxFeeLimitPPM + 1},
		"negative floor":   {InvoiceExpirySeconds: 600, FeeLimitPPM: 10_000, FeeLimitMinMsat: -1},
		"floor over 1000":  {InvoiceExpirySeconds: 600, FeeLimitMinMsat: core.MaxFeeLimitMinMsat + 1},
		"negative percent": {InvoiceExpirySeconds: 600, FeeLimitPPM: -1, FeeLimitMinMsat: 1000},
	} {
		if err := r.svc.UpdateSettings(bad); err == nil {
			t.Errorf("settings accepted: %s", name)
		}
	}
}

// TestOutgoingZapNamesItsRecipient covers what a wallet shows for a zap you
// sent. An invoice names a node and an amount, never a person, so the only
// way a history can say "to Bob" is the zap request the paying app attaches
// to pay_invoice. Damus showed "- 33 to Unknown" because that was dropped.
func TestOutgoingZapNamesItsRecipient(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 500_000_000)
	if _, err := r.svc.Adjust(r.alice, 10_000_000, "opening balance"); err != nil {
		t.Fatal(err)
	}
	zapperSK := nostr.GeneratePrivateKey()
	recipient := strings.Repeat("ab", 32)
	zapRequest := func(to string, msat int64) (nostr.Event, string) {
		ev := nostr.Event{Kind: 9734, CreatedAt: nostr.Now(), Content: "nice", Tags: nostr.Tags{{"p", to}, {"amount", itoa(int(msat))}, {"relays", "wss://relay.example.com"}}}
		if err := ev.Sign(zapperSK); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(ev)
		return ev, string(raw)
	}
	// outgoing returns the transaction list_transactions reports for hash.
	type tx struct {
		Type        string `json:"type"`
		PaymentHash string `json:"payment_hash"`
		Metadata    struct {
			Nostr    *nostr.Event `json:"nostr"`
			Internal bool         `json:"internal"`
		} `json:"metadata"`
	}
	find := func(hash string) *tx {
		t.Helper()
		code, body := r.call("list_transactions", map[string]any{"limit": 50})
		if code != "" {
			t.Fatalf("list_transactions: %s %s", code, body)
		}
		var out struct {
			Result struct {
				Transactions []tx `json:"transactions"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		for i := range out.Result.Transactions {
			if x := &out.Result.Transactions[i]; x.PaymentHash == hash && x.Type == "outgoing" {
				return x
			}
		}
		t.Fatalf("no outgoing transaction %s in %s", hash, body)
		return nil
	}
	// What Damus reads for an outgoing row: the zap request's first p tag.
	namedRecipient := func(x *tx) string {
		if x.Metadata.Nostr == nil {
			return ""
		}
		if p := x.Metadata.Nostr.Tags.GetFirst([]string{"p", ""}); p != nil {
			return (*p)[1]
		}
		return ""
	}
	pay := func(params map[string]any) string {
		t.Helper()
		if code, msg := r.call("pay_invoice", params); code != "" {
			t.Fatalf("pay_invoice: %s %q", code, msg)
		}
		return strings.Split(params["invoice"].(string), "x")[2]
	}

	// 1. NIP-47 metadata, as Damus and others send it for a zap.
	ev, raw := zapRequest(recipient, 33_000)
	h := pay(map[string]any{"invoice": makeFakeInvoice(33_000, false), "description": raw, "metadata": map[string]any{"nostr": ev}})
	if got := namedRecipient(find(h)); got != recipient {
		t.Fatalf("outgoing zap names %q, want the recipient %s", got, recipient)
	}
	// 2. Only the description (the request as a JSON string).
	_, raw = zapRequest(recipient, 21_000)
	h = pay(map[string]any{"invoice": makeFakeInvoice(21_000, false), "description": raw})
	if got := namedRecipient(find(h)); got != recipient {
		t.Fatalf("zap request sent as description: names %q", got)
	}
	// 3. An ordinary payment has no metadata, and a plain description is not one.
	h = pay(map[string]any{"invoice": makeFakeInvoice(5_000, false), "description": "coffee"})
	if x := find(h); x.Metadata.Nostr != nil {
		t.Fatalf("plain payment grew metadata: %+v", x.Metadata)
	}
	// 4. Junk is dropped, and the payment still goes through.
	for name, meta := range map[string]any{
		"too large":     map[string]any{"note": strings.Repeat("x", core.MaxMetadata)},
		"not an object": "just a string",
		"an array":      []int{1, 2, 3},
	} {
		h = pay(map[string]any{"invoice": makeFakeInvoice(1_000, false), "metadata": meta})
		p, err := r.svc.Store().GetPayment(h)
		if err != nil || p.State != store.PaymentSettled || p.Metadata != "" {
			t.Fatalf("%s: payment %+v err %v", name, p, err)
		}
	}

	// 5. A zap to another identity on this node, from an app that sends no
	// metadata at all: the invoice is ours, so its own record names the
	// recipient.
	bob, err := r.svc.NewIdentity("bob", "Bob", "", false, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	_, raw = zapRequest(recipient, 33_000)
	inv, err := r.svc.CreateInvoice(r.ctx, core.CreateInvoiceParams{Identity: bob.Name, AmountMsat: 33_000, ZapRequest: raw, Source: store.SourceZap})
	if err != nil {
		t.Fatal(err)
	}
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": inv.Bolt11}); code != "" {
		t.Fatalf("self-zap: %s %q", code, msg)
	}
	x := find(inv.PaymentHash)
	if got := namedRecipient(x); got != recipient || !x.Metadata.Internal {
		t.Fatalf("self-zap: names %q, internal=%v", got, x.Metadata.Internal)
	}
}

// TestLookupInvoiceFindsPayments covers lookup_invoice for the outgoing side.
// NIP-47 has one lookup for both directions; a wallet that has just paid
// asks about that payment, and used to be told NOT_FOUND because only
// invoices this service issued were searched.
func TestLookupInvoiceFindsPayments(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 500_000_000)
	if _, err := r.svc.Adjust(r.alice, 10_000_000, "opening balance"); err != nil {
		t.Fatal(err)
	}
	type tx struct {
		Type        string `json:"type"`
		State       string `json:"state"`
		Invoice     string `json:"invoice"`
		PaymentHash string `json:"payment_hash"`
		Preimage    string `json:"preimage"`
		Amount      int64  `json:"amount"`
		FeesPaid    int64  `json:"fees_paid"`
		SettledAt   int64  `json:"settled_at"`
	}
	lookup := func(params map[string]any) (string, *tx) {
		t.Helper()
		code, body := r.call("lookup_invoice", params)
		if code != "" {
			return code, nil
		}
		var out struct {
			Result tx `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		return "", &out.Result
	}

	// 1. A settled payment, by hash and by invoice string.
	inv := makeFakeInvoice(250_000, false)
	hash := strings.Split(inv, "x")[2]
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": inv}); code != "" {
		t.Fatalf("pay: %s %q", code, msg)
	}
	for name, params := range map[string]map[string]any{
		"by payment hash":           {"payment_hash": hash},
		"by hash, upper case":       {"payment_hash": strings.ToUpper(hash)},
		"by invoice":                {"invoice": inv},
		"by invoice, as a URI":      {"invoice": "lightning:" + strings.ToUpper(inv)},
		"hash wins when both given": {"payment_hash": hash, "invoice": "lnbc1nonsense"},
	} {
		code, got := lookup(params)
		if code != "" {
			t.Fatalf("%s: %s", name, code)
		}
		if got.Type != "outgoing" || got.State != "settled" || got.PaymentHash != hash || got.Amount != 250_000 ||
			got.FeesPaid != 1_000 || len(got.Preimage) != 64 || got.SettledAt == 0 || got.Invoice != inv {
			t.Fatalf("%s: %+v", name, got)
		}
	}

	// 2. A failed payment is found too, as failed, with no preimage.
	bad := makeFakeInvoice(100_000, true)
	if code, _ := r.call("pay_invoice", map[string]any{"invoice": bad}); code == "" {
		t.Fatal("the failing invoice was paid")
	}
	if code, got := lookup(map[string]any{"payment_hash": strings.Split(bad, "x")[2]}); code != "" || got.Type != "outgoing" || got.State != "failed" || got.Preimage != "" {
		t.Fatalf("failed payment: %s %+v", code, got)
	}

	// 3. An invoice this identity made is still found, as incoming.
	_, body := r.call("make_invoice", map[string]any{"amount": 5_000, "description": "mine"})
	var mi struct {
		Result tx `json:"result"`
	}
	_ = json.Unmarshal([]byte(body), &mi)
	if code, got := lookup(map[string]any{"payment_hash": mi.Result.PaymentHash}); code != "" || got.Type != "incoming" || got.Amount != 5_000 {
		t.Fatalf("own invoice by hash: %s %+v", code, got)
	}
	if code, got := lookup(map[string]any{"invoice": mi.Result.Invoice}); code != "" || got.Type != "incoming" {
		t.Fatalf("own invoice by string: %s %+v", code, got)
	}

	// 4. Nothing leaks across identities, and unknowns are NOT_FOUND.
	bob, err := r.svc.NewIdentity("bob", "Bob", "", false, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	bobConn := &store.Connection{ID: "c-bob", IdentityID: bob.ID, Label: "bob app", ClientPubkey: strings.Repeat("33", 32), Methods: nwc.AllMethods(), CreatedAt: time.Now()}
	if err := r.svc.Store().PutConnection(bobConn); err != nil {
		t.Fatal(err)
	}
	asBob := func(method string, params any) string {
		raw, _ := json.Marshal(params)
		return string(r.nwc.DispatchForTest(r.ctx, bob, bobConn, method, raw))
	}
	for name, params := range map[string]map[string]any{"alice's payment by hash": {"payment_hash": hash}, "alice's payment by invoice": {"invoice": inv}, "alice's invoice": {"payment_hash": mi.Result.PaymentHash}} {
		if res := asBob("lookup_invoice", params); !strings.Contains(res, nwc.ErrNotFound) {
			t.Fatalf("bob can see %s: %s", name, res)
		}
	}
	for name, params := range map[string]map[string]any{
		"unknown hash":    {"payment_hash": strings.Repeat("ef", 32)},
		"unknown invoice": {"invoice": makeFakeInvoice(1_000, false)},
		"not an invoice":  {"invoice": "hello world"},
	} {
		if code, _ := lookup(params); code != nwc.ErrNotFound {
			t.Fatalf("%s: got %q, want NOT_FOUND", name, code)
		}
	}
	if code, _ := lookup(map[string]any{}); code != nwc.ErrOther {
		t.Fatalf("no parameters: %q", code)
	}

	// 5. Alice pays bob's invoice (settled inside the node). One payment
	// hash, two records, two identities: each sees its own side.
	bobInv, err := r.svc.CreateInvoice(r.ctx, core.CreateInvoiceParams{Identity: bob.Name, AmountMsat: 40_000, Source: store.SourceNWC, ConnectionID: bobConn.ID, Description: "to bob"})
	if err != nil {
		t.Fatal(err)
	}
	if code, msg := r.call("pay_invoice", map[string]any{"invoice": bobInv.Bolt11}); code != "" {
		t.Fatalf("pay bob: %s %q", code, msg)
	}
	if code, got := lookup(map[string]any{"payment_hash": bobInv.PaymentHash}); code != "" || got.Type != "outgoing" || got.State != "settled" || got.FeesPaid != 0 {
		t.Fatalf("payer's side: %s %+v", code, got)
	}
	if res := asBob("lookup_invoice", map[string]any{"payment_hash": bobInv.PaymentHash}); !strings.Contains(res, `"type":"incoming"`) || !strings.Contains(res, `"state":"settled"`) {
		t.Fatalf("payee's side: %s", res)
	}

	// 6. Alice pays her own invoice. Both records are hers; the connection
	// that made the invoice is told about the invoice, a connection that
	// only paid is told about the payment.
	payer := &store.Connection{ID: "c-pay2", IdentityID: r.alice.ID, Label: "second app", ClientPubkey: strings.Repeat("44", 32), Methods: nwc.AllMethods(), CreatedAt: time.Now()}
	if err := r.svc.Store().PutConnection(payer); err != nil {
		t.Fatal(err)
	}
	asPayer := func(method string, params any) string {
		raw, _ := json.Marshal(params)
		return string(r.nwc.DispatchForTest(r.ctx, r.alice, payer, method, raw))
	}
	_, body = r.call("make_invoice", map[string]any{"amount": 7_000, "description": "to myself"})
	_ = json.Unmarshal([]byte(body), &mi)
	if res := asPayer("pay_invoice", map[string]any{"invoice": mi.Result.Invoice}); strings.Contains(res, `"code"`) {
		t.Fatalf("self-pay: %s", res)
	}
	if code, got := lookup(map[string]any{"payment_hash": mi.Result.PaymentHash}); code != "" || got.Type != "incoming" || got.State != "settled" {
		t.Fatalf("the connection that made the invoice: %s %+v", code, got)
	}
	if res := asPayer("lookup_invoice", map[string]any{"payment_hash": mi.Result.PaymentHash}); !strings.Contains(res, `"type":"outgoing"`) {
		t.Fatalf("the connection that paid it: %s", res)
	}
}

// TestLiquidityComesFromTheGuard checks the path the dashboard's liquidity
// numbers take: LND -> guard (admin macaroon) -> guard status -> core. Core's
// own credentials cannot read channels, and the guard asks LND at most once
// per LiquidityTTL however often core asks for status.
func TestLiquidityComesFromTheGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	oldTTL := guard.LiquidityTTL
	guard.LiquidityTTL = 400 * time.Millisecond
	defer func() { guard.LiquidityTTL = oldTTL }()
	r := newSendingRig(t, 60_000_000, 500_000_000)

	set := func(chs []map[string]any, fail bool) {
		r.lnd.mu.Lock()
		r.lnd.channels, r.lnd.channelsErr = chs, fail
		r.lnd.mu.Unlock()
		time.Sleep(guard.LiquidityTTL + 100*time.Millisecond) // let the cached reading age out
	}
	read := func() map[string]any {
		t.Helper()
		gs, err := r.svc.GuardStatus(r.ctx)
		if err != nil {
			t.Fatal(err)
		}
		l, _ := gs["liquidity"].(map[string]any)
		if l == nil {
			t.Fatalf("guard status carries no liquidity: %v", gs)
		}
		return l
	}
	num := func(m map[string]any, k string) int64 { f, _ := m[k].(float64); return int64(f) }
	channel := func(alias string, active bool, local, remote int64) map[string]any {
		// LND's REST gateway writes 64-bit numbers as strings.
		return map[string]any{"active": active, "peer_alias": alias, "remote_pubkey": strings.Repeat("02", 33), "private": true,
			"capacity": itoa(int(local + remote)), "local_balance": itoa(int(local)), "remote_balance": itoa(int(remote)),
			"local_constraints": map[string]any{"chan_reserve_sat": "10000"}, "remote_constraints": map[string]any{"chan_reserve_sat": "10000"}}
	}

	// No channels yet.
	set(nil, false)
	if l := read(); num(l, "channels") != 0 || num(l, "can_send_msat") != 0 || l["error"] != nil {
		t.Fatalf("no channels: %v", l)
	}

	// One online channel and one offline.
	set([]map[string]any{channel("LSP", true, 300_000, 700_000), channel("gone", false, 100_000, 100_000)}, false)
	l := read()
	if num(l, "channels") != 2 || num(l, "active") != 1 || num(l, "can_send_msat") != 290_000_000 || num(l, "can_receive_msat") != 690_000_000 || num(l, "offline_send_msat") != 90_000_000 {
		t.Fatalf("summary: %v", l)
	}
	rows, _ := l["list"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows: %v", l["list"])
	}
	// Each row names its peer: the alias, which LND gives only when asked
	// for it, and the node key.
	first, _ := rows[0].(map[string]any)
	if first["peer"] != "LSP" || first["pubkey"] != strings.Repeat("02", 33) {
		t.Fatalf("first row should name its peer by alias and key: %v", first)
	}

	// Asking again and again reads LND once per TTL.
	r.lnd.mu.Lock()
	before := r.lnd.channelCalls
	r.lnd.mu.Unlock()
	for i := 0; i < 20; i++ {
		read()
	}
	r.lnd.mu.Lock()
	extra := r.lnd.channelCalls - before
	r.lnd.mu.Unlock()
	if extra > 1 {
		t.Fatalf("20 status requests read LND's channels %d times", extra)
	}

	// LND failing is reported as such, not as "no channels".
	set(nil, true)
	if l := read(); l["error"] == nil || num(l, "channels") != 0 {
		t.Fatalf("failure: %v", l)
	}

	// The credential core holds cannot read channels itself.
	direct, err := lnd.New(r.lnd.srv.URL, r.lnd.caFile, filepath.Join(filepath.Dir(r.lnd.caFile), "credentials", "recv.macaroon"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := direct.GetInfo(r.ctx); err != nil {
		t.Fatalf("the receive credential should work for what it is for: %v", err)
	}
	if _, err := direct.ListChannels(r.ctx); err == nil || !lnd.IsPermissionDenied(err) {
		t.Fatalf("core's receive credential read the node's channels: %v", err)
	}
}

// TestNWCSpecAlignment pins the points checked against NIP-47 and the NWC
// extension specs (github.com/nostr-wallet-connect/nwc) on 2026-11-12 that
// do not need a relay to observe.
func TestNWCSpecAlignment(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	r := newSendingRig(t, 60_000_000, 500_000_000)
	if _, err := r.svc.Adjust(r.alice, 1_000_000, "opening balance"); err != nil {
		t.Fatal(err)
	}
	result := func(method string, params any) map[string]any {
		t.Helper()
		code, body := r.call(method, params)
		if code != "" {
			t.Fatalf("%s: %s %s", method, code, body)
		}
		var out struct {
			ResultType string         `json:"result_type"`
			Result     map[string]any `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil || out.ResultType != method {
			t.Fatalf("%s reply: %v %s", method, err, body)
		}
		return out.Result
	}

	// get_info names the optional specs implemented, for this connection.
	info := result("get_info", map[string]any{})
	if ext, _ := json.Marshal(info["extensions"]); string(ext) != `["02","05","06"]` {
		t.Fatalf("get_info extensions: %s", ext)
	}
	for _, k := range []string{"alias", "color", "pubkey", "network", "block_height", "block_hash", "methods"} {
		if _, ok := info[k]; !ok {
			t.Errorf("get_info lacks %q", k)
		}
	}

	// make_invoice keeps the app's metadata (NIP-47) and hands it back.
	inv := result("make_invoice", map[string]any{"amount": 5_000, "description": "order 17", "metadata": map[string]any{"comment": "thanks", "recipient_data": map[string]any{"identifier": "alice@pay.example"}}})
	meta, _ := inv["metadata"].(map[string]any)
	if meta["comment"] != "thanks" || meta["recipient_data"] == nil || inv["state"] != "pending" || inv["type"] != "incoming" {
		t.Fatalf("make_invoice result: %v", inv)
	}
	looked := result("lookup_invoice", map[string]any{"payment_hash": inv["payment_hash"]})
	if m, _ := looked["metadata"].(map[string]any); m["comment"] != "thanks" {
		t.Fatalf("lookup_invoice lost the metadata: %v", looked)
	}
	// Metadata over 4096 characters, or that is not an object, is dropped
	// (NWC-06); the invoice is made all the same.
	for name, m := range map[string]any{"too large": map[string]any{"note": strings.Repeat("x", 4096)}, "not an object": "text"} {
		got := result("make_invoice", map[string]any{"amount": 5_000, "metadata": m})
		if got["metadata"] != nil || got["payment_hash"] == nil {
			t.Fatalf("%s metadata: %v", name, got)
		}
	}
	// Exactly at the limit is kept.
	atLimit := map[string]any{"n": strings.Repeat("x", 4096-len(`{"n":""}`))}
	if got := result("make_invoice", map[string]any{"amount": 5_000, "metadata": atLimit}); got["metadata"] == nil {
		t.Fatal("metadata of exactly 4096 characters was dropped")
	}

	// An invoice past its expiry is "expired", the state NIP-47 gives
	// invoices; "failed" belongs to payments.
	short := result("make_invoice", map[string]any{"amount": 5_000, "expiry": 1})
	time.Sleep(1200 * time.Millisecond)
	if got := result("lookup_invoice", map[string]any{"payment_hash": short["payment_hash"]}); got["state"] != "expired" {
		t.Fatalf("expired invoice has state %v", got["state"])
	}
	bad := makeFakeInvoice(100_000, true)
	_, _ = r.call("pay_invoice", map[string]any{"invoice": bad})
	if got := result("lookup_invoice", map[string]any{"payment_hash": strings.Split(bad, "x")[2]}); got["state"] != "failed" {
		t.Fatalf("failed payment has state %v", got["state"])
	}

	// list_transactions: total_count is the number matching the filters
	// before paging (NWC-05). Settled so far: the opening credit and two
	// payments below; unpaid invoices and the failed payment are not listed
	// unless asked for.
	for i := 0; i < 2; i++ {
		if code, msg := r.call("pay_invoice", map[string]any{"invoice": makeFakeInvoice(10_000, false)}); code != "" {
			t.Fatalf("pay: %s %q", code, msg)
		}
	}
	page := result("list_transactions", map[string]any{"limit": 1})
	if txs, _ := page["transactions"].([]any); len(txs) != 1 || page["total_count"] != float64(3) {
		t.Fatalf("limit 1: %d transactions, total_count %v", len(txs), page["total_count"])
	}
	if page = result("list_transactions", map[string]any{"type": "outgoing"}); page["total_count"] != float64(2) {
		t.Fatalf("outgoing total_count: %v", page["total_count"])
	}
	all := result("list_transactions", map[string]any{"unpaid": true})
	states := map[string]int{}
	for _, x := range all["transactions"].([]any) {
		states[fmt.Sprint(x.(map[string]any)["state"])]++
	}
	if states["expired"] != 1 || states["failed"] != 1 || states["pending"] < 3 || states["settled"] != 3 {
		t.Fatalf("states with unpaid=true: %v", states)
	}
}

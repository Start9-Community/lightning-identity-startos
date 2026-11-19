// Package e2e runs guard, core and edge in one process against a fake LND
// and walks the real flows: bake, Lightning Address callback with a zap,
// settlement, receipt on the embedded relay, and an NWC request/response.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/edge"
	"github.com/lundog/lightning-identity-startos/service/internal/guard"
	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/identity"
	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnurl"
	"github.com/lundog/lightning-identity-startos/service/internal/macaroon"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
	"github.com/lundog/lightning-identity-startos/service/internal/relay"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
	"github.com/lundog/lightning-identity-startos/service/internal/zap"
)

func waitFor(t *testing.T, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	dir := t.TempDir()
	// Unix socket paths must stay short; TempDir on some systems is long.
	sockDir, _ := os.MkdirTemp("/tmp", "li")
	defer os.RemoveAll(sockDir)
	lnd := newFakeLND(t, dir)
	me := uint32(os.Getuid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// ---- guard ----
	credDir := filepath.Join(dir, "credentials")
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	g, err := guard.New(guard.Config{
		LNDRestURL: lnd.srv.URL, LNDCAFile: lnd.caFile, AdminMacaroon: lnd.adminMacaroonFile(t, dir),
		CredentialsDir: credDir, StateDir: filepath.Join(dir, "guard"), SocketPath: filepath.Join(sockDir, "g.sock"),
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
	raw, _ := os.ReadFile(filepath.Join(credDir, "recv.macaroon"))
	caveats, err := macaroon.Caveats(strings.ToLower(hexOf(raw)))
	if err != nil || len(caveats) != 2 || !strings.HasPrefix(caveats[0], "time-before ") || caveats[1] != "iprange 127.0.0.0/8" {
		t.Fatalf("baked credential caveats wrong: %v %v", caveats, err)
	}

	// ---- edge (with relay) on a real port ----
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	baseURL := "http://127.0.0.1:" + itoa(port)
	localRelay := "ws://127.0.0.1:" + itoa(port) + "/relay"

	// ---- core ----
	identDir := filepath.Join(dir, "identities")
	svc, err := core.New(core.Config{
		DataDir: filepath.Join(dir, "core"), CredentialsDir: credDir, IdentitiesDir: identDir,
		GuardSocket: filepath.Join(sockDir, "g.sock"), EdgeSocket: filepath.Join(sockDir, "e.sock"), EdgeUIDs: []uint32{me},
		LNDRestURL: lnd.srv.URL, LNDCAFile: lnd.caFile, BaseURL: baseURL, RelayURL: localRelay, LocalRelayURL: localRelay,
		InvoiceExpiry: 10 * time.Minute, Log: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	svc.PublishIdentities()
	n := nwc.New(svc, logger)
	go svc.ServeEdge(ctx)
	go svc.WatchInvoices(ctx)
	go n.Run(ctx)

	ids := identity.NewWatcher(identDir)
	stop := make(chan struct{})
	defer close(stop)
	go ids.Run(stop, 100*time.Millisecond, nil)
	rstore, _ := relay.OpenStore(filepath.Join(dir, "relay.db"))
	defer rstore.Close()
	rl := relay.New(relay.Options{Name: "test", ServiceURL: localRelay, Identities: ids, Store: rstore, Log: log.New(os.Stderr, "[relay] ", 0)})
	es := edge.New(edge.Options{Identities: ids, Core: &ipc.Client{Path: filepath.Join(sockDir, "e.sock"), Timeout: 10 * time.Second}, Relay: rl, Log: logger, InvoicesPerMinute: 1000, RequestsPerMinute: 1000})
	hs := &http.Server{Handler: es}
	go hs.Serve(ln)
	defer hs.Close()

	// ---- identity ----
	userSK := nostr.GeneratePrivateKey()
	userPK, _ := nostr.GetPublicKey(userSK)
	// As cmd/core does: relay dials are held to public addresses unless the
	// operator configured the destination (here, the embedded relay).
	if err := httpx.RestrictOutbound(svc.TrustedDial); err != nil {
		t.Fatal(err)
	}
	alice, err := svc.NewIdentity("alice", "Alice", userPK, true, 1000, 1_000_000_000, 100, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "edge sees alice", 5*time.Second, func() bool { return ids.Doc().Find("alice") != nil })

	// ---- LNURL document + zap callback ----
	res, err := http.Get(baseURL + "/.well-known/lnurlp/alice")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("lnurlp: %v %v", err, res)
	}
	var pay lnurl.PayResponse
	_ = json.NewDecoder(res.Body).Decode(&pay)
	res.Body.Close()
	if pay.NostrPubkey != alice.ZapPubkey || !strings.HasSuffix(pay.Callback, "/lnurlp/alice/callback") {
		t.Fatalf("bad lnurlp: %+v", pay)
	}
	// The zap request is public input, and its relays are URLs core will
	// dial. Two of them point inside: a loopback address, and a hostname
	// that resolves to loopback (the DNS-rebinding shape). A canary listens
	// there; core must never reach it.
	var canaryHits atomic.Int64
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canaryHits.Add(1)
		http.Error(w, "internal service", http.StatusTeapot)
	}))
	defer canary.Close()
	canaryPort := canary.URL[strings.LastIndex(canary.URL, ":")+1:]
	zr := nostr.Event{Kind: zap.KindZapRequest, CreatedAt: nostr.Now(), Content: "gm", Tags: nostr.Tags{{"p", userPK}, {"relays", localRelay, "ws://127.0.0.1:" + canaryPort + "/admin", "ws://localhost:" + canaryPort + "/admin"}, {"amount", "21000"}}}
	senderSK := nostr.GeneratePrivateKey()
	_ = zr.Sign(senderSK)
	zrRaw, _ := json.Marshal(zr)
	res, err = http.Get(pay.Callback + "?amount=21000&nostr=" + url.QueryEscape(string(zrRaw)))
	if err != nil || res.StatusCode != 200 {
		body := ""
		if res != nil {
			var b strings.Builder
			_, _ = copyBody(&b, res)
			body = b.String()
		}
		t.Fatalf("callback: %v %v %s", err, res, body)
	}
	var cb lnurl.CallbackResponse
	_ = json.NewDecoder(res.Body).Decode(&cb)
	res.Body.Close()
	if !strings.HasPrefix(cb.PR, "lnfakex") || cb.Verify == "" {
		t.Fatalf("bad callback: %+v", cb)
	}
	hash := strings.TrimPrefix(cb.Verify, baseURL+"/lnurlp/alice/verify/")
	inv, err := svc.Store().GetInvoice(hash)
	if err != nil || inv.Source != store.SourceZap || inv.AmountMsat != 21000 {
		t.Fatalf("invoice record: %v %+v", err, inv)
	}

	// ---- settle → receipt on the embedded relay ----
	lnd.settle(hash)
	waitFor(t, "invoice settled in store", 10*time.Second, func() bool {
		i, _ := svc.Store().GetInvoice(hash)
		return i != nil && i.State == store.InvoiceSettled
	})
	waitFor(t, "receipt published", 10*time.Second, func() bool {
		i, _ := svc.Store().GetInvoice(hash)
		return i != nil && len(i.ReceiptRelays) > 0
	})
	if n := canaryHits.Load(); n != 0 {
		t.Fatalf("core connected to an internal address named in a zap request (%d requests)", n)
	}
	rc, err := nostr.RelayConnect(ctx, localRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	defer qcancel()
	receipts, err := rc.QuerySync(qctx, nostr.Filter{Kinds: []int{zap.KindZapReceipt}, Tags: nostr.TagMap{"p": []string{userPK}}})
	if err != nil || len(receipts) != 1 || receipts[0].PubKey != alice.ZapPubkey {
		t.Fatalf("receipt query: %v %+v", err, receipts)
	}
	desc := receipts[0].Tags.GetFirst([]string{"description"})
	if desc == nil || (*desc)[1] != string(zrRaw) {
		t.Fatal("receipt description must be the verbatim zap request")
	}

	// LUD-21 verify now reports settled with a preimage
	res, _ = http.Get(cb.Verify)
	var ver lnurl.VerifyResponse
	_ = json.NewDecoder(res.Body).Decode(&ver)
	res.Body.Close()
	if !ver.Settled || ver.Preimage == nil {
		t.Fatalf("verify: %+v", ver)
	}

	// ---- NWC: pair, request make_invoice over the relay, read the response ----
	clientSK := nostr.GeneratePrivateKey()
	clientPK, _ := nostr.GetPublicKey(clientSK)
	conn := &store.Connection{ID: "c1", IdentityID: alice.ID, Label: "test", ClientPubkey: clientPK, Methods: nwc.ReadMethods, Notify: true, CreatedAt: time.Now()}
	if err := svc.Store().PutConnection(conn); err != nil {
		t.Fatal(err)
	}
	svc.PublishIdentities()
	waitFor(t, "relay sees NWC client", 5*time.Second, func() bool { return len(ids.Doc().NWCClients) == 1 })

	ck, _ := nip44.GenerateConversationKey(alice.NWCPubkey, clientSK)
	body, _ := json.Marshal(map[string]any{"method": "make_invoice", "params": map[string]any{"amount": 5000, "description": "nwc test"}})
	enc, _ := nip44.Encrypt(string(body), ck)
	req := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: enc, Tags: nostr.Tags{{"p", alice.NWCPubkey}, {"encryption", "nip44_v2"}}}
	_ = req.Sign(clientSK)

	sub, err := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{nwc.KindResponse}, Tags: nostr.TagMap{"e": []string{req.ID}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Core re-subscribes after identity changes; the relay answers "mute"
	// until its subscription is live, so retry briefly.
	waitFor(t, "NWC request accepted", 10*time.Second, func() bool { return rc.Publish(ctx, req) == nil })
	select {
	case ev := <-sub.Events:
		plain, err := nip44.Decrypt(ev.Content, ck)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			ResultType string          `json:"result_type"`
			Error      json.RawMessage `json:"error"`
			Result     struct {
				Invoice     string `json:"invoice"`
				PaymentHash string `json:"payment_hash"`
				Amount      int64  `json:"amount"`
			} `json:"result"`
		}
		_ = json.Unmarshal([]byte(plain), &out)
		if out.ResultType != "make_invoice" || string(out.Error) != "null" || out.Result.Amount != 5000 || out.Result.Invoice == "" {
			t.Fatalf("nwc response: %s", plain)
		}
		rec, err := svc.Store().GetInvoice(out.Result.PaymentHash)
		if err != nil || rec.ConnectionID != "c1" || rec.Source != store.SourceNWC {
			t.Fatalf("nwc invoice record: %v %+v", err, rec)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no NWC response")
	}

	// A request from an unpaired key is rejected by the relay policy.
	strangerSK := nostr.GeneratePrivateKey()
	bad := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: "x", Tags: nostr.Tags{{"p", alice.NWCPubkey}}}
	_ = bad.Sign(strangerSK)
	if err := rc.Publish(ctx, bad); err == nil {
		t.Fatal("relay accepted an NWC request from an unpaired client")
	}

	// Damus's wallet screen sends its request first and subscribes for the
	// reply afterwards, with a filter naming the request. Core answers in
	// milliseconds, so the reply is published before that subscription
	// exists. The reply must still be there when the subscription arrives.
	body, _ = json.Marshal(map[string]any{"method": "get_balance", "params": map[string]any{}})
	enc, _ = nip44.Encrypt(string(body), ck)
	late := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: enc, Tags: nostr.Tags{{"p", alice.NWCPubkey}, {"encryption", "nip44_v2"}}}
	_ = late.Sign(clientSK)
	if err := rc.Publish(ctx, late); err != nil {
		t.Fatalf("publish request: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // the reply has long been published
	lateSub, err := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{nwc.KindResponse}, Authors: []string{alice.NWCPubkey}, Tags: nostr.TagMap{"e": []string{late.ID}, "p": []string{clientPK}}}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-lateSub.Events:
		plain, err := nip44.Decrypt(ev.Content, ck)
		if err != nil || !strings.Contains(plain, `"balance"`) {
			t.Fatalf("late subscriber got a bad reply: %v %s", err, plain)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a subscription opened just after the request never saw the reply (send-then-subscribe clients get a blank wallet)")
	}
	lateSub.Unsub()

	// NIP-40: an already-expired request is refused by the relay, and one
	// that reaches core some other way is ignored there too (the handler
	// checks the tag itself, since not every relay enforces it).
	expired := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: "x", Tags: nostr.Tags{{"p", alice.NWCPubkey}, {"expiration", fmt.Sprint(time.Now().Add(-time.Minute).Unix())}}}
	_ = expired.Sign(clientSK)
	if err := rc.Publish(ctx, expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("relay should reject an expired request, got %v", err)
	}
	if exp, ok := nwc.Expiration(&expired); !ok || !time.Now().After(exp) {
		t.Fatal("Expiration() did not parse the tag")
	}
	n.HandleForTest(ctx, &expired, "")
	// (nothing to observe but the log; the point is it returns without
	// touching dispatch — a panic or a response would surface below)

	// A wallet's history page must arrive however long the history is. On
	// a real node, Damus (NIP-04, limit 50) got a balance but no
	// transactions: the reply, a dozen zaps with their zap requests, was
	// over the relay's event size limit, the relay refused its own
	// service's event and the app waited for nothing. Sixty zaps here.
	zapReq, _ := json.Marshal(map[string]any{
		"id": strings.Repeat("1", 64), "pubkey": strings.Repeat("2", 64), "sig": strings.Repeat("3", 128), "kind": 9734, "created_at": time.Now().Unix(), "content": "zap",
		"tags": [][]string{{"p", strings.Repeat("4", 64)}, {"amount", "1000"}, append([]string{"relays"}, strings.Fields(strings.Repeat("wss://relay.example.com/a/long/path ", 11))...)},
	})
	for i := 0; i < 60; i++ {
		at := time.Now().Add(-time.Duration(i+1) * time.Minute)
		h := sha256.Sum256([]byte(fmt.Sprint("history", i)))
		if err := svc.Store().PutInvoice(&store.Invoice{
			PaymentHash: hex.EncodeToString(h[:]), IdentityID: alice.ID, Source: store.SourceZap, AmountMsat: 1000, AmtPaidMsat: 1000,
			Bolt11: "lnbc10n1" + strings.Repeat("q", 520), DescriptionHash: strings.Repeat("ab", 32), ZapRequest: string(zapReq),
			CreatedAt: at, ExpiresAt: at.Add(time.Hour), State: store.InvoiceSettled, SettledAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	shared, _ := nip04.ComputeSharedSecret(alice.NWCPubkey, clientSK)
	body, _ = json.Marshal(map[string]any{"method": "list_transactions", "params": map[string]any{"limit": 50, "offset": 0, "unpaid": false}})
	enc, _ = nip04.Encrypt(string(body), shared)
	hist := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: enc, Tags: nostr.Tags{{"p", alice.NWCPubkey}}}
	_ = hist.Sign(clientSK)
	histSub, _ := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{nwc.KindResponse}, Tags: nostr.TagMap{"e": []string{hist.ID}}}})
	if err := rc.Publish(ctx, hist); err != nil {
		t.Fatalf("publish list_transactions: %v", err)
	}
	select {
	case ev := <-histSub.Events:
		if len(ev.Content) <= relay.MaxEventBytes {
			t.Fatalf("test history too small to prove anything: %d bytes", len(ev.Content))
		}
		plain, err := nip04.Decrypt(ev.Content, shared)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				Transactions []struct {
					PaymentHash string         `json:"payment_hash"`
					Preimage    string         `json:"preimage"`
					Amount      int64          `json:"amount"`
					Metadata    map[string]any `json:"metadata"`
				} `json:"transactions"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(plain), &out); err != nil || string(out.Error) != "null" {
			t.Fatalf("list_transactions reply: %v %.300s", err, plain)
		}
		txs := out.Result.Transactions
		if len(txs) != 50 {
			t.Fatalf("asked for 50 transactions, got %d", len(txs))
		}
		if txs[0].Metadata["nostr"] == nil || txs[0].PaymentHash == "" || txs[49].PaymentHash == "" || txs[49].Preimage != "" && len(txs[49].Preimage) != 64 {
			t.Fatalf("history entries incomplete: first=%+v", txs[0])
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no reply to list_transactions for a long history (the relay refused the event?)")
	}
	histSub.Unsub()

	// ---- Conformance with NIP-47 and the NWC extension specs ----
	// The info event says what this service speaks: methods in the content,
	// and tags for encryption, notification types (NWC-02) and the optional
	// specs implemented (02 notifications, 05 list_transactions, 06 metadata).
	infoCtx, infoCancel := context.WithTimeout(ctx, 10*time.Second)
	infos, err := rc.QuerySync(infoCtx, nostr.Filter{Kinds: []int{nwc.KindInfo}, Authors: []string{alice.NWCPubkey}})
	infoCancel()
	if err != nil || len(infos) == 0 {
		t.Fatalf("no info event on the relay: %v", err)
	}
	tagOf := func(ev *nostr.Event, name string) string {
		if tg := ev.Tags.GetFirst([]string{name, ""}); tg != nil {
			return (*tg)[1]
		}
		return ""
	}
	if got := tagOf(infos[0], "encryption"); got != "nip44_v2 nip04" {
		t.Fatalf("info event encryption tag: %q", got)
	}
	if got := tagOf(infos[0], "notifications"); got != "payment_received payment_sent" {
		t.Fatalf("info event notifications tag: %q", got)
	}
	if got := tagOf(infos[0], "extensions"); got != "02 05 06" {
		t.Fatalf("info event extensions tag: %q", got)
	}
	for _, m := range []string{"get_info", "get_balance", "make_invoice", "lookup_invoice", "list_transactions"} {
		if !strings.Contains(" "+infos[0].Content+" ", " "+m+" ") {
			t.Fatalf("info event does not advertise %s: %q", m, infos[0].Content)
		}
	}

	// A notification goes out twice: kind 23197 under NIP-44 and kind 23196
	// under NIP-04 (NWC-02). The two were swapped here once; a client that
	// listens on the kind for its encryption would have got ciphertext it
	// cannot read.
	if nwc.KindNotification != 23197 || nwc.KindNotify04 != 23196 {
		t.Fatalf("notification kinds: nip44=%d nip04=%d, want 23197 and 23196", nwc.KindNotification, nwc.KindNotify04)
	}
	noteSub, err := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{23196, 23197}, Tags: nostr.TagMap{"p": []string{clientPK}}}})
	if err != nil {
		t.Fatal(err)
	}
	rawInv, _ := json.Marshal(map[string]any{"amount": 7000, "description": "notify me"})
	var made struct {
		Result struct {
			PaymentHash string `json:"payment_hash"`
		} `json:"result"`
	}
	_ = json.Unmarshal(n.DispatchForTest(ctx, alice, conn, "make_invoice", rawInv), &made)
	if made.Result.PaymentHash == "" {
		t.Fatal("make_invoice for the notification test failed")
	}
	lnd.settle(made.Result.PaymentHash)
	seen := map[int]bool{}
	deadline := time.After(15 * time.Second)
	for len(seen) < 2 {
		select {
		case ev := <-noteSub.Events:
			var plain string
			var derr error
			if ev.Kind == 23197 {
				plain, derr = nip44.Decrypt(ev.Content, ck)
			} else {
				plain, derr = nip04.Decrypt(ev.Content, shared)
			}
			if derr != nil {
				t.Fatalf("kind %d notification does not decrypt with its encryption: %v", ev.Kind, derr)
			}
			if !strings.Contains(plain, `"notification_type":"payment_received"`) || !strings.Contains(plain, made.Result.PaymentHash) {
				t.Fatalf("kind %d notification: %s", ev.Kind, plain)
			}
			seen[ev.Kind] = true
		case <-deadline:
			t.Fatalf("notifications seen: %v, want kinds 23196 and 23197", seen)
		}
	}
	noteSub.Unsub()

	// A request in an encryption this service does not speak gets
	// UNSUPPORTED_ENCRYPTION, readable with NIP-44, not silence.
	odd := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: "whatever", Tags: nostr.Tags{{"p", alice.NWCPubkey}, {"encryption", "nip99_v7"}}}
	_ = odd.Sign(clientSK)
	oddSub, _ := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{nwc.KindResponse}, Tags: nostr.TagMap{"e": []string{odd.ID}}}})
	if err := rc.Publish(ctx, odd); err != nil {
		t.Fatalf("publish request with odd encryption: %v", err)
	}
	select {
	case ev := <-oddSub.Events:
		plain, err := nip44.Decrypt(ev.Content, ck)
		if err != nil || !strings.Contains(plain, `"code":"UNSUPPORTED_ENCRYPTION"`) {
			t.Fatalf("reply to unsupported encryption: %v %s", err, plain)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no reply to a request with unsupported encryption")
	}
	oddSub.Unsub()

	// pay_invoice is refused while sending is off.
	body, _ = json.Marshal(map[string]any{"method": "pay_invoice", "params": map[string]any{"invoice": "lnbc1..."}})
	enc, _ = nip44.Encrypt(string(body), ck)
	req2 := nostr.Event{Kind: nwc.KindRequest, CreatedAt: nostr.Now(), Content: enc, Tags: nostr.Tags{{"p", alice.NWCPubkey}, {"encryption", "nip44_v2"}}}
	_ = req2.Sign(clientSK)
	sub2, _ := rc.Subscribe(ctx, nostr.Filters{{Kinds: []int{nwc.KindResponse}, Tags: nostr.TagMap{"e": []string{req2.ID}}}})
	_ = rc.Publish(ctx, req2)
	select {
	case ev := <-sub2.Events:
		plain, _ := nip44.Decrypt(ev.Content, ck)
		if !strings.Contains(plain, nwc.ErrRestricted) {
			t.Fatalf("pay_invoice should be RESTRICTED: %s", plain)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no response to pay_invoice")
	}

	// The guard reports over its socket, and core relays it.
	gs, err := svc.GuardStatus(ctx)
	if err != nil || gs["lnd_state"] != "SERVER_ACTIVE" {
		t.Fatalf("guard status: %v %v", err, gs)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

func itoa(i int) string { return strconv.Itoa(i) }

func copyBody(b *strings.Builder, res *http.Response) (int64, error) {
	buf := make([]byte, 4096)
	var n int64
	for {
		k, err := res.Body.Read(buf)
		b.Write(buf[:k])
		n += int64(k)
		if err != nil {
			return n, nil
		}
	}
}

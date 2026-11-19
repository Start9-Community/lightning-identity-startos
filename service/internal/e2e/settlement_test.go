package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// LND's invoice stream is how a payment is normally learned, but a stream
// can stop delivering without ending. These tests pay invoices on the fake
// node WITHOUT an event on the stream, and check that the service still
// finds out: at once when a wallet asks about the invoice, and by itself
// within the periodic check otherwise.

func (r *sendingRig) result(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	code, body := r.call(method, params)
	if code != "" {
		t.Fatalf("%s: %s %s", method, code, body)
	}
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%s reply: %v %s", method, err, body)
	}
	return out.Result
}

func (r *sendingRig) waitSubscribed(t *testing.T, atLeast int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, n := r.lnd.counts(""); n >= atLeast {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, n := r.lnd.counts("")
	t.Fatalf("the invoice stream was opened %d time(s), want at least %d", n, atLeast)
}

func TestLookupAsksTheNodeAboutAnUnpaidInvoice(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	every := core.ReconcileEvery
	core.ReconcileEvery = time.Hour // only the lookup path may find it
	defer func() { core.ReconcileEvery = every }()
	r := newSendingRig(t, 60_000_000, 500_000_000)
	go r.svc.WatchInvoices(r.ctx)
	r.waitSubscribed(t, 1)

	// NWC: the app that made the invoice asks about it.
	inv := r.result(t, "make_invoice", map[string]any{"amount": 21_000, "description": "paid without a stream event"})
	hash := inv["payment_hash"].(string)
	if got := r.result(t, "lookup_invoice", map[string]any{"payment_hash": hash}); got["state"] != "pending" {
		t.Fatalf("unpaid invoice has state %v", got["state"])
	}
	r.lnd.settleSilently(hash, time.Minute)
	got := r.result(t, "lookup_invoice", map[string]any{"payment_hash": hash})
	if got["state"] != "settled" || got["preimage"] == nil || got["settled_at"] == nil {
		t.Fatalf("lookup did not learn of the payment from the node: %v", got)
	}
	if bal := r.result(t, "get_balance", map[string]any{}); bal["balance"] != float64(21_000) {
		t.Fatalf("balance after a payment learned from a lookup: %v", bal["balance"])
	}
	// It is settled exactly once: another lookup changes nothing and no
	// longer asks the node.
	before, _ := r.lnd.counts(hash)
	_ = r.result(t, "lookup_invoice", map[string]any{"payment_hash": hash})
	if after, _ := r.lnd.counts(hash); after != before {
		t.Fatalf("a settled invoice was looked up on the node again (%d -> %d)", before, after)
	}
	if bal := r.result(t, "get_balance", map[string]any{}); bal["balance"] != float64(21_000) {
		t.Fatalf("balance counted twice: %v", bal["balance"])
	}

	// LUD-21 verify, which a payer's wallet polls: same.
	inv = r.result(t, "make_invoice", map[string]any{"amount": 5_000})
	hash = inv["payment_hash"].(string)
	if v, err := r.svc.Verify(r.ctx, hash, ""); err != nil || v.Settled {
		t.Fatalf("verify of an unpaid invoice: %+v %v", v, err)
	}
	r.lnd.settleSilently(hash, time.Minute)
	time.Sleep(3200 * time.Millisecond) // past the per-invoice limit the first verify used up
	if v, err := r.svc.Verify(r.ctx, hash, ""); err != nil || !v.Settled || v.Preimage == nil {
		t.Fatalf("verify did not learn of the payment from the node: %+v %v", v, err)
	}

	// Asking is rate limited per invoice: verify is a public endpoint, and
	// it must not become a way to make this service hammer the node.
	inv = r.result(t, "make_invoice", map[string]any{"amount": 5_000})
	hash = inv["payment_hash"].(string)
	for i := 0; i < 25; i++ {
		_ = r.result(t, "lookup_invoice", map[string]any{"payment_hash": hash})
		_, _ = r.svc.Verify(r.ctx, hash, "")
	}
	if n, _ := r.lnd.counts(hash); n < 1 || n > 3 {
		t.Fatalf("50 lookups of one unpaid invoice asked the node %d times, want 1 to 3", n)
	}
	// Nothing is asked about a hash that is not this service's invoice.
	stranger := strings.Repeat("ab", 32)
	r.svc.RefreshInvoice(r.ctx, stranger)
	if n, _ := r.lnd.counts(stranger); n != 0 {
		t.Fatalf("the node was asked about an invoice that is not ours")
	}
}

func TestPeriodicCheckFindsWhatTheStreamMissed(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	every, grace := core.ReconcileEvery, core.StreamGrace
	core.ReconcileEvery, core.StreamGrace = 200*time.Millisecond, 2*time.Second
	defer func() { core.ReconcileEvery, core.StreamGrace = every, grace }()
	r := newSendingRig(t, 60_000_000, 500_000_000)
	go r.svc.WatchInvoices(r.ctx)
	r.waitSubscribed(t, 1)
	settledWithin := func(hash string, d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if inv, err := r.svc.Store().GetInvoice(hash); err == nil && inv.State == store.InvoiceSettled {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	// A payment the stream delivers is not a missed one: the periodic check
	// may see it first by a moment, and that must not restart the stream.
	inv := r.result(t, "make_invoice", map[string]any{"amount": 3_000})
	r.lnd.settle(inv["payment_hash"].(string))
	if !settledWithin(inv["payment_hash"].(string), 5*time.Second) {
		t.Fatal("a payment delivered by the stream was not settled")
	}
	time.Sleep(600 * time.Millisecond) // three periodic checks
	if _, n := r.lnd.counts(""); n != 1 {
		t.Fatalf("the stream was reopened (%d) though it had missed nothing", n)
	}

	// Nor is a payment the check itself finds first, while it is too fresh
	// for the stream's silence to mean anything: it is settled, and the
	// stream is left alone.
	inv = r.result(t, "make_invoice", map[string]any{"amount": 2_000})
	r.lnd.settleSilently(inv["payment_hash"].(string), 0)
	if !settledWithin(inv["payment_hash"].(string), 5*time.Second) {
		t.Fatal("a fresh payment was not found by the periodic check")
	}
	time.Sleep(1600 * time.Millisecond) // a restarted stream reopens after a second
	if _, n := r.lnd.counts(""); n != 1 {
		t.Fatalf("the stream was reopened (%d) over a payment only moments old", n)
	}

	// Nobody asks about this one. The stream says nothing. The periodic
	// check finds it, and takes it as proof the stream is not delivering.
	inv = r.result(t, "make_invoice", map[string]any{"amount": 8_000})
	hash := inv["payment_hash"].(string)
	r.lnd.settleSilently(hash, 10*time.Second)
	if !settledWithin(hash, 5*time.Second) {
		t.Fatal("a payment the stream never reported was not found by the periodic check")
	}
	r.waitSubscribed(t, 2)
	if bal := r.result(t, "get_balance", map[string]any{}); bal["balance"] != float64(13_000) {
		t.Fatalf("balance: %v, want the three payments counted once each", bal["balance"])
	}

	// The reopened stream works.
	inv = r.result(t, "make_invoice", map[string]any{"amount": 1_000})
	r.lnd.settle(inv["payment_hash"].(string))
	if !settledWithin(inv["payment_hash"].(string), 5*time.Second) {
		t.Fatal("the reopened stream did not deliver a payment")
	}
}

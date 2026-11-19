package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentitiesAndNames(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := &Identity{ID: "a", Name: "Alice", CreatedAt: time.Now()}
	if err := s.PutIdentity(a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIdentityByName("ALICE"); err != nil {
		t.Fatalf("name lookup is case-insensitive: %v", err)
	}
	b := &Identity{ID: "b", Name: "alice"}
	if err := s.PutIdentity(b); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("expected ErrNameTaken, got %v", err)
	}
	a.Name = "alicia"
	if err := s.PutIdentity(a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIdentityByName("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old name should be released")
	}
	c := &Connection{ID: "c1", IdentityID: "a", ClientPubkey: "pk", Methods: []string{"get_info"}, CreatedAt: time.Now()}
	if err := s.PutConnection(c); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteIdentity("a"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetConnection("c1")
	if got.RevokedAt == nil {
		t.Fatal("deleting an identity must revoke its connections")
	}
}

func TestInvoicesOrderAndPending(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		inv := &Invoice{PaymentHash: string(rune('a' + i)), IdentityID: "x", CreatedAt: base.Add(time.Duration(i) * time.Minute), State: InvoiceOpen}
		if i%2 == 0 {
			inv.ZapRequest = "{}"
		}
		if err := s.PutInvoice(inv); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.ListInvoices("x", 0, 10)
	if len(list) != 5 || list[0].PaymentHash != "e" {
		t.Fatalf("expected newest first, got %+v", list)
	}
	page, _ := s.ListInvoices("x", 2, 2)
	if len(page) != 2 || page[0].PaymentHash != "c" {
		t.Fatalf("pagination wrong: %+v", page)
	}
	pend, _ := s.PendingZaps()
	if len(pend) != 3 {
		t.Fatalf("expected 3 pending zaps, got %d", len(pend))
	}
	inv, _ := s.GetInvoice("a")
	inv.State = InvoiceSettled
	inv.ReceiptID = "r"
	_ = s.PutInvoice(inv)
	pend, _ = s.PendingZaps()
	if len(pend) != 2 {
		t.Fatalf("receipted zap should leave pending set, got %d", len(pend))
	}
}

func TestSealerAndReseal(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "t.db"))
	defer s.Close()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	s1, _ := NewSealer(k1)
	s2, _ := NewSealer(k2)
	enc, _ := s1.Seal([]byte("secret"))
	_ = s.PutIdentity(&Identity{ID: "i", Name: "i", ZapSecretEnc: enc, NWCSecretEnc: enc})
	if err := s.Reseal(s1, s2); err != nil {
		t.Fatal(err)
	}
	id, _ := s.GetIdentity("i")
	if pt, err := s2.Open(id.ZapSecretEnc); err != nil || string(pt) != "secret" {
		t.Fatalf("reseal failed: %v", err)
	}
	if _, err := s1.Open(id.ZapSecretEnc); err == nil {
		t.Fatal("old key must not open resealed value")
	}
}

func TestIdentityBalance(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	// Two settled invoices (one overpaid), one still open, one for someone else.
	for _, inv := range []*Invoice{
		{PaymentHash: "i1", IdentityID: "a", AmountMsat: 10_000, AmtPaidMsat: 10_000, State: InvoiceSettled, CreatedAt: now},
		{PaymentHash: "i2", IdentityID: "a", AmountMsat: 5_000, AmtPaidMsat: 6_000, State: InvoiceSettled, CreatedAt: now.Add(time.Second)},
		{PaymentHash: "i3", IdentityID: "a", AmountMsat: 99_000, State: InvoiceOpen, CreatedAt: now.Add(2 * time.Second)},
		{PaymentHash: "i4", IdentityID: "b", AmountMsat: 50_000, AmtPaidMsat: 50_000, State: InvoiceSettled, CreatedAt: now},
	} {
		if err := s.PutInvoice(inv); err != nil {
			t.Fatal(err)
		}
	}
	// A settled, a pending and a failed payment.
	for _, p := range []*Payment{
		{PaymentHash: "p1", IdentityID: "a", ConnectionID: "c", AmountMsat: 3_000, FeeLimitMsat: 1_000, FeeMsat: 10, State: PaymentSettled, CreatedAt: now},
		{PaymentHash: "p2", IdentityID: "a", ConnectionID: "c", AmountMsat: 2_000, FeeLimitMsat: 1_000, State: PaymentPending, CreatedAt: now},
		{PaymentHash: "p3", IdentityID: "a", ConnectionID: "c", AmountMsat: 70_000, FeeLimitMsat: 1_000, State: PaymentFailed, CreatedAt: now},
	} {
		if err := s.PutPayment(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutAdjustment(&Adjustment{ID: "x1", IdentityID: "a", AmountMsat: 100_000, Note: "opening", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdjustment(&Adjustment{ID: "x2", IdentityID: "a", AmountMsat: -40_000, CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdjustment(&Adjustment{ID: "x3", IdentityID: "a", AmountMsat: 0, CreatedAt: now}); err == nil {
		t.Fatal("zero adjustment must be refused")
	}
	b, err := s.IdentityBalance("a")
	if err != nil {
		t.Fatal(err)
	}
	want := Balance{Received: 16_000, Sent: 3_010, InFlight: 3_000, Adjusted: 60_000, Available: 16_000 + 60_000 - 3_010 - 3_000}
	if b != want {
		t.Fatalf("balance: got %+v want %+v", b, want)
	}
	if ob, _ := s.IdentityBalance("b"); ob.Available != 50_000 {
		t.Fatalf("other identity: %+v", ob)
	}
	if nb, _ := s.IdentityBalance("nobody"); nb != (Balance{}) {
		t.Fatalf("unknown identity: %+v", nb)
	}
	adjs, _ := s.ListAdjustments("a", 0, 10)
	if len(adjs) != 2 || adjs[0].ID != "x2" {
		t.Fatalf("adjustments newest first: %+v", adjs)
	}
}

// A retried payment replaces its row. It must then be counted once: the
// first version of PutPayment left the failed attempt's index entry behind,
// and every balance and budget saw the settled retry twice.
func TestRetriedPaymentCountedOnce(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Now().Add(-time.Minute)
	if err := s.PutPayment(&Payment{PaymentHash: "h", IdentityID: "a", ConnectionID: "c", AmountMsat: 5_000, FeeLimitMsat: 1_000, State: PaymentFailed, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPayment(&Payment{PaymentHash: "h", IdentityID: "a", ConnectionID: "c", AmountMsat: 5_000, FeeLimitMsat: 1_000, FeeMsat: 7, State: PaymentSettled, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	b, _ := s.IdentityBalance("a")
	if b.Sent != 5_007 {
		t.Fatalf("retried payment counted %d msat sent, want 5007", b.Sent)
	}
	if spent, _ := s.ConnectionSpent("c", time.Time{}); spent != 5_007 {
		t.Fatalf("connection spent %d, want 5007", spent)
	}
	if list, _ := s.ListPayments("a", 0, 10); len(list) != 1 {
		t.Fatalf("history shows %d rows for one payment", len(list))
	}
}

func TestUpdateInvoiceIsCompareAndSet(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.PutInvoice(&Invoice{PaymentHash: "i", IdentityID: "a", AmountMsat: 1_000, State: InvoiceOpen, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	settle := func(inv *Invoice) bool {
		if inv.State == InvoiceSettled {
			return false
		}
		inv.State, inv.AmtPaidMsat = InvoiceSettled, 1_000
		return true
	}
	cancel := func(inv *Invoice) bool {
		if inv.State != InvoiceOpen {
			return false
		}
		inv.State = InvoiceCanceled
		return true
	}
	// Settle, then a stale cancellation: the settlement stands.
	if _, err := s.UpdateInvoice("i", settle); err != nil {
		t.Fatal(err)
	}
	if inv, _ := s.UpdateInvoice("i", cancel); inv.State != InvoiceSettled {
		t.Fatalf("a cancellation overwrote a settlement: %s", inv.State)
	}
	if _, err := s.UpdateInvoice("missing", settle); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing invoice: %v", err)
	}
}

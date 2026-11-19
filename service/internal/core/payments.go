package core

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// Payment limits core applies before the guard ever sees a request. They are
// the soft layer: the guard's caps hold even if every line here is wrong.
const (
	// The default fee limit: 1 % of the amount, but at least 10 sats. The
	// first version had a 1-sat floor, and small zaps failed with "no
	// route" on any path of two hops or more. Operators change both in the
	// Admin UI.
	DefaultFeeLimitPPM     = 10_000
	DefaultFeeLimitMinMsat = 10_000
	MaxFeeLimitPPM         = 100_000   // 10 %
	MaxFeeLimitMinMsat     = 1_000_000 // 1000 sats
	PaymentTimeoutSecond   = 60
)

// SendWait is how long PayInvoice waits for LND's verdict before answering
// the wallet: a little longer than the pathfinding timeout it gives LND. A
// var so tests can shorten it.
var SendWait = (PaymentTimeoutSecond + 15) * time.Second

// ErrSendingDisabled is returned while no spend credential exists.
var ErrSendingDisabled = errors.New("sending is not enabled on this service")

// ErrBudget is returned when a connection's own budget would be exceeded.
type ErrBudget struct{ Msg string }

func (e *ErrBudget) Error() string { return e.Msg }

// ErrInsufficientBalance is returned when the identity's own ledger balance
// cannot cover a payment plus its fee reserve.
type ErrInsufficientBalance struct{ Available, Need int64 }

func (e *ErrInsufficientBalance) Error() string {
	return fmt.Sprintf("insufficient balance: %d msat available, %d msat needed including the fee reserve", e.Available, e.Need)
}

// ErrSelfPayDisabled is returned for one of this node's own invoices while
// self-pay is off: LND cannot route to itself, so refusing early is kinder
// than a "no route" after a timeout.
var ErrSelfPayDisabled = errors.New("this invoice was issued by this node and cannot be paid over Lightning; enable self-pay in the Admin UI to settle it internally")

// ErrPaymentFailed carries LND's failure reason.
type ErrPaymentFailed struct{ Reason string }

func (e *ErrPaymentFailed) Error() string { return "payment failed: " + e.Reason }

var spendMu sync.Mutex

// SendingEnabled reports whether a spend credential exists right now.
func (s *Service) SendingEnabled() bool {
	st, err := statFile(filepath.Join(s.cfg.CredentialsDir, "spend.macaroon"))
	return err == nil && st > 0
}

// spendLND returns a client holding the spend credential.
func (s *Service) spendLND() (*lnd.Client, error) {
	c, err := lnd.New(s.cfg.LNDRestURL, s.cfg.LNDCAFile, "")
	if err != nil {
		return nil, err
	}
	if err := c.LoadMacaroon(filepath.Join(s.cfg.CredentialsDir, "spend.macaroon")); err != nil {
		return nil, ErrSendingDisabled
	}
	return c, nil
}

// PayInvoice pays a bolt11 on behalf of a connection, within the connection's
// budget, through the spend credential, and records the outcome.
// MaxMetadata bounds the metadata an app may attach to a payment or an
// invoice: 4096 characters, the limit the NWC metadata conventions (NWC-06)
// set so that a transaction stays small enough to relay. Larger metadata is
// dropped, as that spec requires.
const MaxMetadata = 4096

// PayInvoice pays bolt11 for a connection. metadata is the paying app's own
// note about the payment (a JSON object, or empty); it is stored with the
// payment and plays no part in paying it.
func (s *Service) PayInvoice(ctx context.Context, id *store.Identity, conn *store.Connection, bolt11 string, amountMsat int64, metadata string) (*store.Payment, error) {
	if strings.TrimSpace(bolt11) == "" {
		return nil, errors.New("invoice is required")
	}
	bolt11, err := lnd.NormalizeBolt11(bolt11)
	if err != nil {
		return nil, errors.New("that is not a lightning invoice")
	}
	if amountMsat < 0 {
		return nil, errors.New("amount cannot be negative")
	}
	if !s.SendingEnabled() {
		return nil, ErrSendingDisabled
	}
	cli, err := s.spendLND()
	if err != nil {
		return nil, err
	}
	pr, err := cli.DecodePayReq(ctx, bolt11)
	if err != nil {
		return nil, fmt.Errorf("invoice could not be decoded: %w", err)
	}
	amount := int64(pr.NumMsat)
	if amount == 0 {
		amount = amountMsat
	} else if amountMsat != 0 && amountMsat != amount {
		return nil, errors.New("amount does not match the invoice")
	}
	if amount <= 0 {
		return nil, errors.New("the invoice has no amount; pass one")
	}
	if int64(pr.Timestamp)+int64(pr.Expiry) < time.Now().Unix() {
		return nil, errors.New("the invoice has expired")
	}
	// One of our own? Then Lightning cannot carry it (a node has no route to
	// itself) and the ledger settles it instead, if the operator allows.
	if own, err := s.store.GetInvoice(pr.PaymentHash); err == nil {
		if !s.Settings().SelfPay {
			return nil, ErrSelfPayDisabled
		}
		return s.payInternal(ctx, id, conn, own, pr, amount, metadata)
	}
	feeLimit := FeeLimit(amount, s.Settings())
	total := amount + feeLimit

	// Soft limits: the identity's balance, then the connection's own limits,
	// under a lock so two concurrent requests cannot both squeeze under
	// either. (The guard's caps are the hard layer behind all of this.)
	spendMu.Lock()
	// One payment per invoice: a row that is pending or settled is final
	// until LND says otherwise. Only a failed attempt may be retried.
	if existing, err := s.store.GetPayment(pr.PaymentHash); err == nil && existing.State != store.PaymentFailed {
		spendMu.Unlock()
		if existing.State == store.PaymentPending {
			return nil, errors.New("this invoice is already being paid: the earlier payment is still in flight")
		}
		return nil, errors.New("this invoice has already been paid")
	}
	bal, err := s.store.IdentityBalance(id.ID)
	if err != nil {
		spendMu.Unlock()
		return nil, err
	}
	if bal.Available < total {
		spendMu.Unlock()
		return nil, &ErrInsufficientBalance{Available: bal.Available, Need: total}
	}
	if conn.MaxPayMsat > 0 && total > conn.MaxPayMsat {
		spendMu.Unlock()
		return nil, &ErrBudget{fmt.Sprintf("payment of %d msat (with fee reserve) exceeds this connection's per-payment limit of %d msat", total, conn.MaxPayMsat)}
	}
	if conn.BudgetMsat > 0 {
		spent, err := s.store.ConnectionSpent(conn.ID, store.PeriodStart(conn.BudgetPeriod, time.Now()))
		if err != nil {
			spendMu.Unlock()
			return nil, err
		}
		if spent+total > conn.BudgetMsat {
			spendMu.Unlock()
			return nil, &ErrBudget{fmt.Sprintf("payment of %d msat would exceed this connection's budget (%d of %d msat used)", total, spent, conn.BudgetMsat)}
		}
	}
	p := &store.Payment{
		PaymentHash:  pr.PaymentHash,
		IdentityID:   id.ID,
		ConnectionID: conn.ID,
		AmountMsat:   amount,
		FeeLimitMsat: feeLimit,
		Bolt11:       bolt11,
		Description:  pr.Description,
		Destination:  pr.Destination,
		State:        store.PaymentPending,
		CreatedAt:    time.Now().UTC(),
		Metadata:     metadata,
	}
	if err := s.store.PutPayment(p); err != nil {
		spendMu.Unlock()
		return nil, err
	}
	spendMu.Unlock()

	req := lnd.SendPaymentRequest{PaymentRequest: bolt11, FeeLimitMsat: lnd.Int64(feeLimit), TimeoutSeconds: PaymentTimeoutSecond, NoInflightUpd: true}
	if int64(pr.NumMsat) == 0 {
		req.AmtMsat = lnd.Int64(amount)
	}
	// The row is pending and holds the balance from here on. The send runs
	// on its own clock: the caller going away (a wallet disconnecting, the
	// NWC subscription restarting) must not cut it short, and nothing about
	// the caller decides how the payment is booked.
	s.markSending(p.PaymentHash, true)
	defer s.markSending(p.PaymentHash, false)
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), SendWait)
	defer cancel()
	res, err := cli.SendPaymentV2(pctx, req)

	var refused *lnd.Error
	switch {
	case err == nil && res.Status == "SUCCEEDED":
		s.settlePayment(p, res)
		return p, nil
	case err == nil:
		// LND's own terminal verdict.
		s.failPayment(p, res.FailureReason)
		return p, &ErrPaymentFailed{Reason: res.FailureReason}
	case errors.As(err, &refused) && strings.Contains(refused.Message, "guard:"):
		// The guard refuses at the request intercept, before LND's handler
		// runs: nothing was started. (It never rejects a response.)
		s.failPayment(p, guardReason(err))
		return p, &ErrPaymentFailed{Reason: guardReason(err)}
	case errors.As(err, &refused) && lnd.IsPermissionDenied(err):
		// The macaroon itself was refused: also before anything started.
		s.failPayment(p, err.Error())
		return p, ErrSendingDisabled
	}
	// Anything else — a timeout, a dropped connection, an error LND raised
	// without saying how the payment ended — is not a failure. The payment
	// may be in flight (a hold invoice is the adversarial case: the
	// recipient accepts the HTLC, waits for us to give up, then settles).
	// Only LND's record of the payment can release the balance.
	s.log.Warn("payment outcome unknown; asking LND", "hash", p.PaymentHash, "err", err)
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer rcancel()
	switch s.resolvePayment(rctx, cli, p, err) {
	case store.PaymentSettled:
		return p, nil
	case store.PaymentFailed:
		return p, &ErrPaymentFailed{Reason: p.FailureReason}
	default:
		return p, ErrPaymentPending
	}
}

// ErrPaymentPending is returned when a payment is still in flight after the
// wait: not failed, not settled, balance still held.
var ErrPaymentPending = errors.New("the payment is still in flight on the node; it has not failed, the amount stays reserved, and it will be booked as sent or released when the node resolves it")

func (s *Service) markSending(hash string, on bool) {
	s.sendingMu.Lock()
	defer s.sendingMu.Unlock()
	if s.sending == nil {
		s.sending = map[string]bool{}
	}
	if on {
		s.sending[hash] = true
	} else {
		delete(s.sending, hash)
	}
}

func (s *Service) isSending(hash string) bool {
	s.sendingMu.Lock()
	defer s.sendingMu.Unlock()
	return s.sending[hash]
}

func (s *Service) settlePayment(p *store.Payment, res *lnd.Payment) {
	p.State = store.PaymentSettled
	p.FeeMsat = int64(res.FeeMsat)
	if int64(res.ValueMsat) > 0 {
		p.AmountMsat = int64(res.ValueMsat)
	}
	p.FailureReason = ""
	p.SettledAt = time.Now().UTC()
	if pre, err := hex.DecodeString(res.PaymentPreimage); err == nil && len(pre) == 32 {
		if enc, err := s.sealer.Seal(pre); err == nil {
			p.PreimageEnc = enc
		}
	}
	if err := s.store.PutPayment(p); err != nil {
		s.log.Error("store settled payment", "hash", p.PaymentHash, "err", err)
	}
	s.log.Info("payment settled", "hash", p.PaymentHash, "msat", p.AmountMsat, "fee_msat", p.FeeMsat, "connection", p.ConnectionID)
}

func (s *Service) failPayment(p *store.Payment, reason string) {
	p.State = store.PaymentFailed
	p.FailureReason = reason
	if err := s.store.PutPayment(p); err != nil {
		s.log.Error("store failed payment", "hash", p.PaymentHash, "err", err)
	}
	s.log.Warn("payment failed", "hash", p.PaymentHash, "reason", reason)
}

// resolvePayment books a pending payment from LND's own record of it and
// returns the resulting state. The rule is one-sided on purpose: the row
// leaves "pending" only on a definite answer. LND never started it, or says
// it failed: the balance is released. LND says it succeeded: it is settled.
// In flight, or LND cannot be asked: it stays pending and keeps holding the
// balance, for as long as that takes.
func (s *Service) resolvePayment(ctx context.Context, cli *lnd.Client, p *store.Payment, cause error) string {
	tp, err := cli.TrackPayment(ctx, p.PaymentHash)
	switch {
	case errors.Is(err, lnd.ErrPaymentNotFound):
		reason := "the node never started this payment"
		if cause != nil {
			reason = guardReason(cause)
		}
		s.failPayment(p, reason)
	case err != nil:
		s.log.Warn("payment still unresolved: LND could not be asked", "hash", p.PaymentHash, "err", err)
	case int64(tp.CreationTimeNs) > 0 && time.Unix(0, int64(tp.CreationTimeNs)).Before(p.CreatedAt.Add(-5*time.Second)):
		// LND's payment for this hash is older than our attempt: the node
		// paid (or is paying) this invoice by other means, and refused ours.
		// It is not this identity's payment and must not be debited to it.
		s.failPayment(p, "this node already paid, or is paying, this invoice outside this service")
	case tp.Status == "SUCCEEDED":
		s.settlePayment(p, tp)
	case tp.Status == "FAILED":
		s.failPayment(p, tp.FailureReason)
	default:
		s.log.Info("payment still in flight", "hash", p.PaymentHash, "status", tp.Status)
	}
	return p.State
}

// guardReason strips LND's gRPC framing from a middleware rejection so the
// NWC client sees the guard's sentence.
func guardReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "guard:"); i >= 0 {
		return strings.TrimSpace(msg[i:])
	}
	return msg
}

// ReconcileInterval is how often pending payments are checked against LND.
// A var so tests can shorten it.
var ReconcileInterval = 30 * time.Second

// ReconcilePayments resolves pending payments — ones that outlived the
// wallet's wait, or a restart — from LND's record, for as long as ctx lives.
// There is no timeout after which a pending payment is assumed failed: a
// hold invoice can stay in flight for days, and assuming is how balances get
// spent twice.
func (s *Service) ReconcilePayments(ctx context.Context) {
	t := time.NewTicker(ReconcileInterval)
	defer t.Stop()
	for {
		s.ReconcilePaymentsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReconcilePaymentsOnce makes one pass over the pending payments. It needs
// the spend credential (TrackPaymentV2 is one of its three methods); while
// sending is disabled nothing can be looked up and pending rows simply keep
// holding their balance.
func (s *Service) ReconcilePaymentsOnce(ctx context.Context) {
	pend, err := s.store.PendingPayments()
	if err != nil || len(pend) == 0 {
		return
	}
	cli, err := s.spendLND()
	if err != nil {
		s.log.Warn("pending payments cannot be resolved while sending is disabled; their balance stays held", "count", len(pend))
		return
	}
	for _, p := range pend {
		if s.isSending(p.PaymentHash) || p.Internal {
			continue // a live PayInvoice owns this row
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		state := s.resolvePayment(rctx, cli, p, nil)
		cancel()
		if state == store.PaymentSettled && s.nwc != nil {
			s.nwc.PaymentSettled(p)
		}
	}
}

// Preimage unseals a settled payment's preimage as hex.
func (s *Service) Preimage(enc []byte) string {
	if len(enc) == 0 {
		return ""
	}
	pre, err := s.sealer.Open(enc)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(pre)
}

// Balance is the identity's ledger position.
func (s *Service) Balance(identityID string) (store.Balance, error) {
	return s.store.IdentityBalance(identityID)
}

// Adjust credits (positive) or debits (negative) an identity's balance. It is
// bookkeeping only: nothing moves on the node, and the sum of all identity
// balances is not checked against the node's liquidity, so a credited
// identity can still hit INSUFFICIENT_BALANCE at LND. Taken under the spend
// lock so a debit cannot race a payment's balance check.
func (s *Service) Adjust(id *store.Identity, amountMsat int64, note string) (*store.Adjustment, error) {
	if amountMsat == 0 {
		return nil, errors.New("amount must not be zero")
	}
	note = strings.TrimSpace(note)
	if len(note) > 200 {
		return nil, errors.New("note is too long (200 characters)")
	}
	a := &store.Adjustment{ID: newID(), IdentityID: id.ID, AmountMsat: amountMsat, Note: note, CreatedAt: time.Now().UTC()}
	spendMu.Lock()
	defer spendMu.Unlock()
	if err := s.store.PutAdjustment(a); err != nil {
		return nil, err
	}
	s.log.Info("balance adjusted", "identity", id.Name, "msat", amountMsat, "note", note)
	return a, nil
}

// payInternal settles one of this node's own invoices without a Lightning
// payment: the payer's identity is debited, the payee's invoice is settled
// in the ledger with the real preimage (LND returns it for its own
// invoices), and the LND invoice is cancelled first so it can never also be
// paid over the network. No fee, no route, no guard involvement — nothing
// leaves the node. Budgets and balances apply exactly as for a real payment.
func (s *Service) payInternal(ctx context.Context, id *store.Identity, conn *store.Connection, inv *store.Invoice, pr *lnd.PayReq, amount int64, metadata string) (*store.Payment, error) {
	if inv.State != store.InvoiceOpen {
		return nil, fmt.Errorf("this invoice is already %s", inv.State)
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, errors.New("the invoice has expired")
	}
	recv, err := s.LND()
	if err != nil {
		return nil, err
	}
	li, err := recv.LookupInvoice(ctx, inv.PaymentHash)
	if err != nil {
		return nil, fmt.Errorf("look up own invoice: %w", err)
	}
	if li.State != "OPEN" {
		return nil, fmt.Errorf("this invoice is %s on the node", strings.ToLower(li.State))
	}
	if len(li.RPreimage) != 32 {
		return nil, errors.New("the node did not return the invoice preimage")
	}

	spendMu.Lock()
	bal, err := s.store.IdentityBalance(id.ID)
	if err != nil {
		spendMu.Unlock()
		return nil, err
	}
	if bal.Available < amount {
		spendMu.Unlock()
		return nil, &ErrInsufficientBalance{Available: bal.Available, Need: amount}
	}
	if conn.MaxPayMsat > 0 && amount > conn.MaxPayMsat {
		spendMu.Unlock()
		return nil, &ErrBudget{fmt.Sprintf("payment of %d msat exceeds this connection's per-payment limit of %d msat", amount, conn.MaxPayMsat)}
	}
	if conn.BudgetMsat > 0 {
		spent, err := s.store.ConnectionSpent(conn.ID, store.PeriodStart(conn.BudgetPeriod, time.Now()))
		if err != nil {
			spendMu.Unlock()
			return nil, err
		}
		if spent+amount > conn.BudgetMsat {
			spendMu.Unlock()
			return nil, &ErrBudget{fmt.Sprintf("payment of %d msat would exceed this connection's budget (%d of %d msat used)", amount, spent, conn.BudgetMsat)}
		}
	}
	if existing, err := s.store.GetPayment(pr.PaymentHash); err == nil && existing.State != store.PaymentFailed {
		spendMu.Unlock()
		return nil, errors.New("this invoice is already being paid")
	}
	// Reserve the invoice on the node before touching the ledger: if it was
	// settled over Lightning a moment ago, CancelInvoice fails and so do we.
	if err := recv.CancelInvoice(ctx, li.RHash); err != nil {
		spendMu.Unlock()
		return nil, fmt.Errorf("could not reserve the invoice on the node: %w", err)
	}
	now := time.Now().UTC()
	p := &store.Payment{
		PaymentHash:  pr.PaymentHash,
		IdentityID:   id.ID,
		ConnectionID: conn.ID,
		AmountMsat:   amount,
		Bolt11:       inv.Bolt11,
		Description:  pr.Description,
		Destination:  pr.Destination,
		State:        store.PaymentSettled,
		CreatedAt:    now,
		SettledAt:    now,
		Internal:     true,
		Metadata:     metadata,
	}
	if enc, err := s.sealer.Seal(li.RPreimage); err == nil {
		p.PreimageEnc = enc
	}
	if err := s.store.PutPayment(p); err != nil {
		spendMu.Unlock()
		return nil, err
	}
	spendMu.Unlock()
	// Settle the payee's side outside the lock: it publishes the receipt and
	// NWC notifications. Nothing can race it — the invoice is cancelled on
	// the node and the payer's row is written.
	if cur, err := s.store.GetInvoice(inv.PaymentHash); err == nil {
		inv = cur
	}
	s.settleInvoice(ctx, inv, li.RPreimage, amount, now, "internal")
	s.log.Info("self-payment settled", "hash", p.PaymentHash, "msat", amount, "from", id.Name, "to_identity", inv.IdentityID, "connection", conn.ID)
	return p, nil
}

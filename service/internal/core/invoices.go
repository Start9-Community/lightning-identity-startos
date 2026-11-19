package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/lnurl"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
	"github.com/lundog/lightning-identity-startos/service/internal/zap"
)

// Caps on what any single identity may have outstanding, so an attacker who
// can only ask for invoices cannot fill LND's invoice database.
const (
	MaxOpenInvoicesPerIdentity = 500
	MaxOpenInvoicesTotal       = 5000
)

// CreateInvoiceParams is the one internet-originating request core serves,
// after edge validated it and before core validates it again.
type CreateInvoiceParams struct {
	Identity     string
	AmountMsat   int64
	Comment      string
	PayerData    string
	ZapRequest   string
	Source       string // lnurl, zap, nwc
	ConnectionID string
	Description  string // NWC make_invoice description
	DescHashHex  string // NWC make_invoice description_hash
	Expiry       time.Duration
	// Metadata is the JSON object an app attached to make_invoice, already
	// checked for shape and size by the caller; kept verbatim.
	Metadata string
}

// CreateInvoice re-validates and creates an invoice on LND.
func (s *Service) CreateInvoice(ctx context.Context, p CreateInvoiceParams) (*store.Invoice, error) {
	id, err := s.store.GetIdentityByName(p.Identity)
	if err != nil || id.Disabled {
		return nil, errors.New("unknown address")
	}
	if s.Domain() == "" {
		return nil, errors.New("no public domain is configured for this service")
	}
	min, max := lnurl.ClampBounds(id.MinSendableMsat, id.MaxSendableMsat)
	if p.AmountMsat < min || p.AmountMsat > max {
		return nil, fmt.Errorf("amount must be between %d and %d msat", min, max)
	}
	if err := s.checkOpenCaps(id.ID); err != nil {
		return nil, err
	}

	address := id.Name + "@" + s.Domain()
	inv := &store.Invoice{
		IdentityID:   id.ID,
		ConnectionID: p.ConnectionID,
		Source:       p.Source,
		AmountMsat:   p.AmountMsat,
		CreatedAt:    time.Now().UTC(),
		State:        store.InvoiceOpen,
		Metadata:     p.Metadata,
	}
	settings := s.Settings()
	expiry := p.Expiry
	if expiry <= 0 {
		expiry = time.Duration(settings.InvoiceExpirySeconds) * time.Second
	}
	inv.ExpiresAt = inv.CreatedAt.Add(expiry)

	req := lnd.AddInvoiceRequest{ValueMsat: lnd.Int64(p.AmountMsat), Expiry: lnd.Int64(expiry.Seconds()), Private: settings.RouteHints}
	switch {
	case p.ZapRequest != "":
		zr, err := zap.Validate(p.ZapRequest, p.AmountMsat)
		if err != nil {
			return nil, err
		}
		if len(p.ZapRequest) > lnurl.MaxZapRequest {
			return nil, errors.New("zap request too large")
		}
		h := sha256.Sum256([]byte(p.ZapRequest))
		req.DescriptionHash = h[:]
		inv.Source = store.SourceZap
		inv.ZapRequest = p.ZapRequest
		inv.DescriptionHash = hex.EncodeToString(h[:])
		inv.Description = "zap for " + address
		_ = zr
	case p.DescHashHex != "":
		raw, err := hex.DecodeString(p.DescHashHex)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("description_hash must be 32 bytes hex")
		}
		req.DescriptionHash = raw
		inv.DescriptionHash = p.DescHashHex
		inv.Description = p.Description
	case p.Source == store.SourceNWC:
		desc := p.Description
		if len(desc) > 640 {
			desc = desc[:640]
		}
		req.Memo = desc
		inv.Description = desc
	default:
		meta := lnurl.Metadata(address, id.DisplayName)
		h := lnurl.MetadataHash(meta)
		req.DescriptionHash = h
		inv.DescriptionHash = hex.EncodeToString(h)
		inv.Description = "payment to " + address
	}
	if p.Comment != "" {
		if err := lnurl.ValidateComment(id.CommentAllowed, p.Comment); err != nil {
			return nil, err
		}
		inv.Comment = p.Comment
	}
	if p.PayerData != "" {
		clean, err := lnurl.ValidatePayerData(p.PayerData)
		if err != nil {
			return nil, err
		}
		inv.PayerData = clean
	}

	cli, err := s.LND()
	if err != nil {
		return nil, err
	}
	res, err := cli.AddInvoice(ctx, req)
	if err != nil {
		s.forgetNode()
		s.log.Warn("AddInvoice failed", "identity", id.Name, "err", err)
		return nil, errors.New("the node could not create an invoice")
	}
	inv.PaymentHash = res.RHash.Hex()
	inv.Bolt11 = res.PaymentRequest
	if err := s.store.PutInvoice(inv); err != nil {
		return nil, err
	}
	if err := s.bumpAddIndex(int64(res.AddIndex)); err != nil {
		s.log.Warn("meta", "err", err)
	}
	s.log.Info("invoice created", "identity", id.Name, "msat", p.AmountMsat, "source", inv.Source, "hash", inv.PaymentHash)
	return inv, nil
}

func (s *Service) checkOpenCaps(identityID string) error {
	open, err := s.store.OpenInvoices()
	if err != nil {
		return err
	}
	if len(open) >= MaxOpenInvoicesTotal {
		return errors.New("too many unpaid invoices outstanding; try again later")
	}
	n := 0
	for _, inv := range open {
		if inv.IdentityID == identityID {
			n++
		}
	}
	if n >= MaxOpenInvoicesPerIdentity {
		return errors.New("too many unpaid invoices outstanding for this address; try again later")
	}
	return nil
}

func (s *Service) bumpAddIndex(idx int64) error {
	m, err := s.store.GetMeta()
	if err != nil {
		return err
	}
	if idx > m.LastAddIndex {
		m.LastAddIndex = idx
		return s.store.PutMeta(m)
	}
	return nil
}

// Verify answers LUD-21 for a payment hash created by this service.
func (s *Service) Verify(ctx context.Context, hash, identityName string) (*lnurl.VerifyResponse, error) {
	hash = strings.ToLower(hash)
	inv, err := s.store.GetInvoice(hash)
	if err != nil {
		return nil, errors.New("unknown invoice")
	}
	if identityName != "" {
		id, err := s.store.GetIdentity(inv.IdentityID)
		if err != nil || id.Name != strings.ToLower(identityName) {
			return nil, errors.New("unknown invoice")
		}
	}
	// A payer's wallet polls this right after paying. Ask LND, so the answer
	// does not wait on the stream.
	if inv.State == store.InvoiceOpen {
		s.RefreshInvoice(ctx, hash)
		if cur, err := s.store.GetInvoice(hash); err == nil {
			inv = cur
		}
	}
	res := &lnurl.VerifyResponse{Status: "OK", PR: inv.Bolt11, Settled: inv.State == store.InvoiceSettled}
	if res.Settled && len(inv.PreimageEnc) > 0 {
		if pre, err := s.sealer.Open(inv.PreimageEnc); err == nil {
			h := hex.EncodeToString(pre)
			res.Preimage = &h
		}
	}
	return res, nil
}

// The stream is how a settlement is normally learned, within milliseconds.
// It is not the only way, because a stream can stop delivering without
// ending: then nothing here would notice, an invoice paid on the node would
// stay "pending" in every wallet, and no receipt or notification would go
// out until the next reconnect. So open invoices are also checked against
// LND directly: all of them every ReconcileEvery, and one at once when a
// wallet asks about it (RefreshInvoice).
var (
	// ReconcileEvery is how often every open invoice is looked up in LND.
	ReconcileEvery = 2 * time.Minute
	// StreamGrace: a settlement the periodic check finds is taken as missed
	// by the stream, and the stream restarted, only once it is this old. A
	// check that merely lands between a payment and its event proves
	// nothing.
	StreamGrace = 30 * time.Second
)

const (
	// The newest open invoices looked up per pass; unpaid ones expire
	// within the invoice expiry, so there are rarely more than a handful.
	reconcileMax = 500
	// RefreshInvoice asks LND about one invoice at most this often, and
	// about all invoices together at most refreshPerMinute times a minute:
	// LUD-21 verify is a public endpoint, and it must not become a way to
	// make this service hammer the node.
	refreshEachPerMinute = 20
	refreshPerMinute     = 300
)

// WatchInvoices follows LND's invoice stream, reconnecting forever, and
// processes settlements and cancellations. It also runs the periodic check
// described above.
func (s *Service) WatchInvoices(ctx context.Context) {
	go s.reconcileLoop(ctx)
	backoff := time.Second
	for ctx.Err() == nil {
		cli, err := s.LND()
		if err != nil {
			s.log.Info("invoice watcher: waiting for credential", "err", err)
			sleep(ctx, 10*time.Second)
			continue
		}
		m, _ := s.store.GetMeta()
		s.log.Info("invoice watcher: subscribing", "add_index", m.LastAddIndex, "settle_index", m.LastSettleIndex)
		// Catch up on anything that settled while we were away.
		s.reconcilePending(ctx, cli)
		sctx, stop := context.WithCancel(ctx)
		s.watchMu.Lock()
		s.restartStream = stop
		s.watchMu.Unlock()
		err = cli.SubscribeInvoices(sctx, m.LastAddIndex, m.LastSettleIndex, func(inv *lnd.Invoice) error {
			backoff = time.Second
			s.onInvoiceUpdate(ctx, inv)
			return nil
		})
		stop()
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("invoice watcher: stream ended", "err", err)
		s.forgetNode()
		sleep(ctx, backoff)
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// reconcilePending looks every open invoice up in LND (the newest
// reconcileMax of them) and applies what it finds. It returns how many
// settlements it found that the stream had had ample time to deliver.
func (s *Service) reconcilePending(ctx context.Context, cli *lnd.Client) (missed int) {
	open, err := s.store.OpenInvoices()
	if err != nil {
		return 0
	}
	sort.Slice(open, func(i, j int) bool { return open[i].CreatedAt.After(open[j].CreatedAt) })
	if len(open) > reconcileMax {
		open = open[:reconcileMax]
	}
	for _, inv := range open {
		if ctx.Err() != nil {
			return missed
		}
		li, err := cli.LookupInvoice(ctx, inv.PaymentHash)
		if err != nil {
			continue
		}
		if s.onInvoiceUpdate(ctx, li) && time.Since(time.Unix(int64(li.SettleDate), 0)) > StreamGrace {
			missed++
		}
	}
	return missed
}

// reconcileLoop is the periodic half of the safety net. Finding a
// settlement the stream should long since have delivered means the stream
// is not delivering, so it is restarted as well.
func (s *Service) reconcileLoop(ctx context.Context) {
	for {
		sleep(ctx, ReconcileEvery)
		if ctx.Err() != nil {
			return
		}
		cli, err := s.LND()
		if err != nil {
			continue
		}
		if missed := s.reconcilePending(ctx, cli); missed > 0 {
			s.log.Warn("invoice watcher: settlements reached LND but not the stream; restarting the stream", "found", missed)
			s.watchMu.Lock()
			restart := s.restartStream
			s.watchMu.Unlock()
			if restart != nil {
				restart()
			}
		}
	}
}

// RefreshInvoice asks LND about one of this service's invoices that is
// still open here, and applies the answer. It is called when a wallet looks
// an invoice up (NWC lookup_invoice, LUD-21 verify), so that the answer is
// LND's and not only what the stream has delivered so far. It does nothing
// for an invoice that is not ours or no longer open, and it is rate limited
// per invoice and overall; when over a limit the caller simply answers from
// the ledger, as it did before.
func (s *Service) RefreshInvoice(ctx context.Context, hash string) {
	hash = strings.ToLower(hash)
	inv, err := s.store.GetInvoice(hash)
	if err != nil || inv.State != store.InvoiceOpen {
		return
	}
	if !s.refreshEach.Allow(hash) || !s.refreshAll.Allow("") {
		return
	}
	cli, err := s.LND()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	li, err := cli.LookupInvoice(ctx, hash)
	if err != nil {
		return
	}
	if s.onInvoiceUpdate(ctx, li) {
		s.log.Info("invoice settled, learned from a lookup before the stream", "hash", hash)
	}
}

// onInvoiceUpdate applies LND's view of one invoice and reports whether
// that settled it here just now.
func (s *Service) onInvoiceUpdate(ctx context.Context, li *lnd.Invoice) (settledNow bool) {
	hash := li.RHash.Hex()
	inv, err := s.store.GetInvoice(hash)
	if err != nil {
		return false // not ours
	}
	m, _ := s.store.GetMeta()
	changed := false
	if int64(li.AddIndex) > m.LastAddIndex {
		m.LastAddIndex = int64(li.AddIndex)
		changed = true
	}
	if int64(li.SettleIndex) > m.LastSettleIndex {
		m.LastSettleIndex = int64(li.SettleIndex)
		changed = true
	}
	if changed {
		_ = s.store.PutMeta(m)
	}
	switch li.State {
	case "SETTLED":
		if inv.State == store.InvoiceSettled {
			return false
		}
		settledAt := time.Unix(int64(li.SettleDate), 0).UTC()
		if settledAt.Before(inv.CreatedAt) {
			settledAt = time.Now().UTC()
		}
		return s.settleInvoice(ctx, inv, li.RPreimage, int64(li.AmtPaidMsat), settledAt, "lightning")
	case "CANCELED":
		// Only an invoice that is still open can become cancelled, decided
		// against the stored row: self-pay cancels the LND invoice just
		// before settling ours, and this must never undo that settlement.
		_, _ = s.store.UpdateInvoice(inv.PaymentHash, func(cur *store.Invoice) bool {
			if cur.State != store.InvoiceOpen {
				return false
			}
			cur.State = store.InvoiceCanceled
			if time.Now().After(cur.ExpiresAt) {
				cur.State = store.InvoiceExpired
			}
			return true
		})
	}
	return false
}

// settleInvoice records a settlement — from LND's subscription or from an
// internal self-payment — and triggers the zap receipt and NWC notification.
func (s *Service) settleInvoice(ctx context.Context, inv *store.Invoice, preimage []byte, amtPaidMsat int64, settledAt time.Time, how string) (first bool) {
	var enc []byte
	if len(preimage) > 0 {
		enc, _ = s.sealer.Seal(preimage)
	}
	// One transition, decided against the stored row: an invoice is settled
	// (and its receipt and notifications sent) exactly once, whatever order
	// LND's subscription, a reconnect sweep and a self-payment arrive in.
	cur, err := s.store.UpdateInvoice(inv.PaymentHash, func(cur *store.Invoice) bool {
		if cur.State == store.InvoiceSettled {
			return false
		}
		first = true
		cur.State = store.InvoiceSettled
		cur.AmtPaidMsat = amtPaidMsat
		cur.SettledAt = settledAt
		if enc != nil {
			cur.PreimageEnc = enc
		}
		return true
	})
	if err != nil {
		s.log.Error("store settled invoice", "err", err)
		return false
	}
	if !first {
		return false
	}
	*inv = *cur
	s.log.Info("invoice settled", "hash", inv.PaymentHash, "msat", inv.AmtPaidMsat, "source", inv.Source, "via", how)
	if inv.ZapRequest != "" {
		go s.publishReceipt(ctx, inv, preimage)
	}
	if s.nwc != nil {
		s.nwc.InvoiceSettled(inv)
	}
	return true
}

func (s *Service) publishReceipt(ctx context.Context, inv *store.Invoice, preimage []byte) {
	id, err := s.store.GetIdentity(inv.IdentityID)
	if err != nil {
		return
	}
	req, err := zap.Validate(inv.ZapRequest, inv.AmountMsat)
	if err != nil {
		s.log.Warn("zap receipt: stored request no longer validates", "hash", inv.PaymentHash, "err", err)
		return
	}
	sk, err := s.ZapSecret(id)
	if err != nil {
		s.log.Error("zap receipt: unseal key", "err", err)
		return
	}
	ev, err := zap.Receipt(req, inv.Bolt11, hex.EncodeToString(preimage), inv.SettledAt, sk)
	if err != nil {
		s.log.Error("zap receipt: sign", "err", err)
		return
	}
	// The request's relays are a stranger's input: cleaned and capped here,
	// and held to public addresses when dialled.
	relays := untrustedRelays(req.Relays)
	relays = append(relays, s.RelaysFor(id)...)
	if s.cfg.LocalRelayURL != "" {
		relays = append(relays, s.cfg.LocalRelayURL)
	}
	relays = s.DialRelays(relays)
	ok := s.pub.Publish(ctx, relays, ev)
	inv.ReceiptID = ev.ID
	inv.ReceiptAt = time.Now().UTC()
	inv.ReceiptRelays = ok
	inv.ReceiptAttempts++
	_ = s.store.PutInvoice(inv)
	s.log.Info("zap receipt published", "hash", inv.PaymentHash, "relays_ok", len(ok), "relays_tried", len(relays))
}

// RetryReceipts republishes receipts that reached no relay, with backoff by
// attempt count, and marks expired invoices.
func (s *Service) RetryReceipts(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.sweepExpired()
		hashes, err := s.store.PendingZaps()
		if err != nil {
			continue
		}
		for _, h := range hashes {
			inv, err := s.store.GetInvoice(h)
			if err != nil || inv.State != store.InvoiceSettled {
				continue
			}
			if len(inv.ReceiptRelays) > 0 || inv.ReceiptAttempts >= 10 {
				continue
			}
			if time.Since(inv.ReceiptAt) < time.Duration(inv.ReceiptAttempts)*5*time.Minute {
				continue
			}
			var pre []byte
			if len(inv.PreimageEnc) > 0 {
				pre, _ = s.sealer.Open(inv.PreimageEnc)
			}
			s.publishReceipt(ctx, inv, pre)
		}
	}
}

func (s *Service) sweepExpired() {
	open, err := s.store.OpenInvoices()
	if err != nil {
		return
	}
	now := time.Now()
	for _, inv := range open {
		if now.After(inv.ExpiresAt.Add(2 * time.Minute)) {
			inv.State = store.InvoiceExpired
			_ = s.store.PutInvoice(inv)
		}
	}
}

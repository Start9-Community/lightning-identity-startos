// Package nwc implements the wallet-service side of NIP-47 (Nostr Wallet
// Connect) for every identity: a service key per identity, connections with
// per-connection permissions, requests over the embedded relay (and any
// relays the operator added), NIP-44 with NIP-04 fallback, and payment
// notifications. Spending is refused outright until the guard's latch exists
// (phase 2); every read and receive method works today.
package nwc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// NIP-47 kinds. Notifications (NWC-02) go out twice when both encryptions
// are supported: kind 23197 encrypted with NIP-44, and kind 23196 encrypted
// with NIP-04 for clients that have not moved on. (These two were the other
// way round here until the spec alignment of 2026-11-12.)
const (
	KindInfo         = 13194
	KindRequest      = 23194
	KindResponse     = 23195
	KindNotification = 23197
	KindNotify04     = 23196
)

// Methods this service implements. pay_invoice is advertised only once the
// guard has a spend credential, which phase 1 never has.
var (
	ReadMethods   = []string{"get_info", "get_balance", "make_invoice", "lookup_invoice", "list_transactions"}
	SpendMethods  = []string{"pay_invoice"}
	Notifications = []string{"payment_received", "payment_sent"}
	Encryptions   = []string{"nip44_v2", "nip04"}
	// Extensions are the optional NWC specifications this service
	// implements, by number, as advertised in the info event and get_info:
	// 02 notifications, 05 list_transactions, 06 metadata conventions.
	// (github.com/nostr-wallet-connect/nwc; NIP-47 itself is the core.)
	Extensions = []string{"02", "05", "06"}
)

// AllMethods a connection may be granted.
func AllMethods() []string { return append(append([]string{}, ReadMethods...), SpendMethods...) }

// Error codes from NIP-47.
const (
	ErrRateLimited    = "RATE_LIMITED"
	ErrNotImplemented = "NOT_IMPLEMENTED"
	ErrInsufficient   = "INSUFFICIENT_BALANCE"
	ErrQuota          = "QUOTA_EXCEEDED"
	ErrRestricted     = "RESTRICTED"
	ErrUnauthorized   = "UNAUTHORIZED"
	ErrInternal       = "INTERNAL"
	ErrOther          = "OTHER"
	ErrNotFound       = "NOT_FOUND"
	ErrEncryption     = "UNSUPPORTED_ENCRYPTION"
)

type nwcError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *nwcError) Error() string { return e.Code + ": " + e.Message }

func fail(code, msg string) error { return &nwcError{Code: code, Message: msg} }

// Service is the running NWC side.
type Service struct {
	core *core.Service
	log  *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	seen    map[string]time.Time
	restart chan struct{}
	started time.Time // when this process began serving
}

// spending reports whether the spend credential exists right now; the guard
// creates and removes that file, so this is the live truth.
func (s *Service) spending() bool { return s.core.SendingEnabled() }

// Expiration returns the event's NIP-40 expiration, if it has a valid one.
func Expiration(ev *nostr.Event) (time.Time, bool) {
	t := ev.Tags.GetFirst([]string{"expiration", ""})
	if t == nil || len(*t) < 2 {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(strings.TrimSpace((*t)[1]), 10, 64)
	if err != nil || secs <= 0 {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}

// InfoRepublish is how often every identity's info event is resent even
// when nothing changed. A var so tests can shorten it.
var InfoRepublish = 10 * time.Minute

// New builds the service and registers it with core for settle events.
func New(c *core.Service, log *slog.Logger) *Service {
	s := &Service{core: c, log: log, seen: map[string]time.Time{}, restart: make(chan struct{}, 1), started: time.Now()}
	c.SetNWC(s)
	return s
}

// IdentitiesChanged restarts the subscription with the current key set.
func (s *Service) IdentitiesChanged() {
	select {
	case s.restart <- struct{}{}:
	default:
	}
}

// Run subscribes to requests and serves them until ctx ends, restarting the
// subscription whenever identities or connections change.
func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
		subCtx, cancel := context.WithCancel(ctx)
		go s.subscribe(subCtx)
		go s.publishInfoAll(subCtx)
		select {
		case <-ctx.Done():
			cancel()
			return
		case <-s.restart:
			cancel()
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// relaysFor is where an identity's NWC traffic is read and written: its own
// relay if it has one, else the embedded relay (over loopback).
func (s *Service) relaysFor(id *store.Identity) []string {
	return s.core.NWCDialRelaysFor(id)
}

func (s *Service) subscribe(ctx context.Context) {
	ids, err := s.core.Store().ListIdentities()
	if err != nil || len(ids) == 0 {
		return
	}
	// One subscription over the union of every identity's relay; a relay
	// sees every service pubkey in the filter, which reveals nothing (the
	// pubkeys are public in every connection string) and keeps this a
	// single stream.
	var pubkeys, relays []string
	seen := map[string]bool{}
	for _, id := range ids {
		if id.Disabled {
			continue
		}
		pubkeys = append(pubkeys, id.NWCPubkey)
		for _, r := range s.relaysFor(id) {
			if !seen[r] {
				seen[r] = true
				relays = append(relays, r)
			}
		}
	}
	if len(pubkeys) == 0 {
		return
	}
	// Look back two minutes, so a request that arrived while this
	// subscription was restarting is picked up (the relay keeps requests
	// for a minute, and `seen` drops the ones already handled) — but never
	// to before this process started: `seen` begins empty then, and a
	// request answered by the previous process must not be run again.
	lookback := time.Now().Add(-2 * time.Minute)
	if lookback.Before(s.started) {
		lookback = s.started
	}
	since := nostr.Timestamp(lookback.Unix())
	filter := nostr.Filter{Kinds: []int{KindRequest}, Tags: nostr.TagMap{"p": pubkeys}, Since: &since}
	pool := s.core.Publisher().Pool()
	s.log.Info("nwc: subscribed", "services", len(pubkeys), "relays", relays)
	for ev := range pool.SubscribeMany(ctx, relays, filter) {
		if ev.Event == nil {
			continue
		}
		if s.alreadySeen(ev.ID) {
			continue
		}
		relayURL := ""
		if ev.Relay != nil {
			relayURL = ev.Relay.URL
		}
		// Detached from the subscription's context: that one is cancelled
		// whenever identities change, and a request in the middle of a
		// payment must run to its answer regardless.
		go s.handle(context.WithoutCancel(ctx), ev.Event, relayURL)
	}
}

func (s *Service) alreadySeen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.seen) > 4096 {
		for k, t := range s.seen {
			if now.Sub(t) > 10*time.Minute {
				delete(s.seen, k)
			}
		}
	}
	if _, ok := s.seen[id]; ok {
		return true
	}
	s.seen[id] = now
	return false
}

type request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type response struct {
	ResultType string    `json:"result_type"`
	Error      *nwcError `json:"error"`
	Result     any       `json:"result"`
}

func (s *Service) handle(ctx context.Context, ev *nostr.Event, relayURL string) {
	target := ""
	if p := ev.Tags.GetFirst([]string{"p", ""}); p != nil && len(*p) >= 2 {
		target = (*p)[1]
	}
	// Every event the subscription delivers is logged, paired or not: a
	// request from an unknown client is the first thing to look for when a
	// wallet "does nothing".
	s.log.Info("nostr: received", "kind", ev.Kind, "id", ev.ID, "pubkey", ev.PubKey, "p", target, "relay", relayURL, "created_at", ev.CreatedAt.Time().UTC().Format(time.RFC3339))
	if ok, err := ev.CheckSignature(); err != nil || !ok {
		s.log.Warn("nwc: bad signature", "id", ev.ID, "pubkey", ev.PubKey)
		return
	}
	// NIP-40: a request that carries an expiration in the past is dead on
	// arrival, whether or not the relay enforced it. A wallet sets this so
	// a payment request it gave up on is never executed late.
	if exp, ok := Expiration(ev); ok && time.Now().After(exp) {
		s.log.Info("nwc: expired request ignored", "id", ev.ID, "pubkey", ev.PubKey, "expired_at", exp.UTC().Format(time.RFC3339))
		return
	}
	if target == "" {
		s.log.Warn("nwc: request without p tag", "id", ev.ID, "pubkey", ev.PubKey)
		return
	}
	id, err := s.identityByNWCPubkey(target)
	if err != nil {
		s.log.Warn("nwc: request for unknown service pubkey", "id", ev.ID, "pubkey", ev.PubKey, "p", target)
		return
	}
	conn, err := s.core.Store().GetConnectionByClient(ev.PubKey)
	if err != nil || conn.IdentityID != id.ID {
		s.log.Warn("nwc: request from unpaired client", "id", ev.ID, "pubkey", ev.PubKey, "identity", id.Name)
		return
	}
	svcSK, err := s.core.NWCSecret(id)
	if err != nil {
		s.log.Error("nwc: unseal service key", "err", err)
		return
	}
	scheme, ok := requestEncryption(ev)
	if !ok {
		// The request names a scheme this service does not speak, so it
		// cannot be read, and the client is owed UNSUPPORTED_ENCRYPTION
		// rather than silence. The reply uses NIP-44, the one scheme every
		// implementation must have.
		s.log.Warn("nwc: request with unsupported encryption", "id", ev.ID, "pubkey", ev.PubKey, "encryption", scheme)
		s.respond(ctx, id, conn, ev, "nip44_v2", relayURL, response{Error: &nwcError{ErrEncryption, "unsupported encryption " + strconv.Quote(scheme) + "; this wallet service supports " + strings.Join(Encryptions, " and ")}})
		return
	}
	plain, err := decrypt(scheme, ev.Content, ev.PubKey, svcSK)
	if err != nil {
		s.log.Warn("nwc: undecryptable request", "id", ev.ID, "pubkey", ev.PubKey, "encryption", scheme, "err", err)
		return
	}
	var req request
	if err := json.Unmarshal([]byte(plain), &req); err != nil {
		s.log.Warn("nwc: request is not JSON", "id", ev.ID, "pubkey", ev.PubKey)
		s.respond(ctx, id, conn, ev, scheme, relayURL, response{ResultType: "", Error: &nwcError{ErrOther, "request is not JSON"}})
		return
	}
	res := response{ResultType: req.Method}
	result, herr := s.dispatch(ctx, id, conn, req)
	if herr != nil {
		var ne *nwcError
		if errors.As(herr, &ne) {
			res.Error = ne
		} else {
			res.Error = &nwcError{ErrInternal, herr.Error()}
		}
		s.log.Info("nwc: request", "method", req.Method, "identity", id.Name, "connection", conn.Label, "client", ev.PubKey, "encryption", scheme, "error", res.Error.Code, "message", res.Error.Message)
	} else {
		s.log.Info("nwc: request", "method", req.Method, "identity", id.Name, "connection", conn.Label, "client", ev.PubKey, "encryption", scheme, "ok", true)
		res.Result = result
	}
	now := time.Now().UTC()
	conn.LastUsedAt = &now
	_ = s.core.Store().PutConnection(conn)
	s.respond(ctx, id, conn, ev, scheme, relayURL, res)
}

// requestEncryption reads which encryption a request uses from its
// `encryption` tag: "nip44_v2", or "nip04", which is also what a missing tag
// means (the original protocol had no tag). Anything else is reported back
// as it was written, with ok false.
func requestEncryption(ev *nostr.Event) (scheme string, ok bool) {
	t := ev.Tags.GetFirst([]string{"encryption", ""})
	if t == nil || len(*t) < 2 {
		return "nip04", true
	}
	switch v := strings.TrimSpace((*t)[1]); v {
	case "nip44_v2":
		return "nip44_v2", true
	case "nip04", "":
		return "nip04", true
	default:
		if len(v) > 32 {
			v = v[:32]
		}
		return v, false
	}
}

func (s *Service) identityByNWCPubkey(pk string) (*store.Identity, error) {
	ids, err := s.core.Store().ListIdentities()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if id.NWCPubkey == pk && !id.Disabled {
			return id, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Service) respond(ctx context.Context, id *store.Identity, conn *store.Connection, req *nostr.Event, scheme, relayURL string, res response) {
	svcSK, err := s.core.NWCSecret(id)
	if err != nil {
		return
	}
	body, _ := json.Marshal(res)
	content, err := encrypt(scheme, string(body), conn.ClientPubkey, svcSK)
	if limit := s.resultBudget(id) * 3 / 2; err != nil || len(content) > limit {
		// A reply that cannot be encrypted (NIP-44 stops at 65,535 bytes)
		// or that the relay would refuse. Say so, rather than leave the
		// wallet waiting for an event that never arrives.
		s.log.Error("nwc: response does not fit in one event", "method", res.ResultType, "plain_bytes", len(body), "content_bytes", len(content), "limit", limit, "err", err)
		body, _ = json.Marshal(response{ResultType: res.ResultType, Error: &nwcError{Code: ErrInternal, Message: "the response is too large to send over the relay"}})
		if content, err = encrypt(scheme, string(body), conn.ClientPubkey, svcSK); err != nil {
			s.log.Error("nwc: encrypt response", "err", err)
			return
		}
	}
	ev := &nostr.Event{
		Kind:      KindResponse,
		CreatedAt: nostr.Now(),
		Content:   content,
		Tags:      nostr.Tags{{"p", conn.ClientPubkey}, {"e", req.ID}},
	}
	if scheme == "nip44_v2" {
		ev.Tags = append(ev.Tags, nostr.Tag{"encryption", "nip44_v2"})
	}
	if err := ev.Sign(svcSK); err != nil {
		return
	}
	// Answer on the identity's relay and on the relay the request came in
	// on, which are usually the same one: dedupe, or the pool publishes
	// twice to one relay and the second attempt hangs until the deadline.
	relays := s.core.DialRelays(append(s.relaysFor(id), relayURL))
	s.core.Publisher().Publish(ctx, relays, ev)
}

func decrypt(scheme, content, peerPub, sk string) (string, error) {
	if scheme == "nip44_v2" {
		ck, err := nip44.GenerateConversationKey(peerPub, sk)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(content, ck)
	}
	shared, err := nip04.ComputeSharedSecret(peerPub, sk)
	if err != nil {
		return "", err
	}
	return nip04.Decrypt(content, shared)
}

func encrypt(scheme, plain, peerPub, sk string) (string, error) {
	if scheme == "nip44_v2" {
		ck, err := nip44.GenerateConversationKey(peerPub, sk)
		if err != nil {
			return "", err
		}
		return nip44.Encrypt(plain, ck)
	}
	shared, err := nip04.ComputeSharedSecret(peerPub, sk)
	if err != nil {
		return "", err
	}
	return nip04.Encrypt(plain, shared)
}

// ---- methods ----

func (s *Service) dispatch(ctx context.Context, id *store.Identity, conn *store.Connection, req request) (any, error) {
	if !conn.Active(time.Now()) {
		return nil, fail(ErrUnauthorized, "this connection has been revoked or has expired")
	}
	if !conn.Allows(req.Method) && req.Method != "get_info" {
		return nil, fail(ErrRestricted, "this connection is not allowed to call "+req.Method)
	}
	switch req.Method {
	case "get_info":
		return s.getInfo(ctx, conn)
	case "get_balance":
		return s.getBalance(ctx, id, conn)
	case "make_invoice":
		return s.makeInvoice(ctx, id, conn, req.Params)
	case "lookup_invoice":
		return s.lookupInvoice(ctx, id, conn, req.Params)
	case "list_transactions":
		return s.listTransactions(ctx, id, req.Params)
	case "pay_invoice":
		return s.payInvoice(ctx, id, conn, req.Params)
	case "pay_keysend", "multi_pay_invoice", "multi_pay_keysend":
		return nil, fail(ErrNotImplemented, "this wallet service does not support "+req.Method)
	default:
		return nil, fail(ErrNotImplemented, "unknown method "+req.Method)
	}
}

func (s *Service) getInfo(ctx context.Context, conn *store.Connection) (any, error) {
	info, err := s.core.NodeInfo(ctx)
	if err != nil {
		return nil, fail(ErrInternal, "node unavailable")
	}
	network := "mainnet"
	if len(info.Chains) > 0 && info.Chains[0].Network != "" {
		network = info.Chains[0].Network
	}
	methods := []string{}
	for _, m := range conn.Methods {
		if m == "pay_invoice" && !s.spending() {
			continue
		}
		methods = append(methods, m)
	}
	notif := []string{}
	if conn.Notify {
		notif = Notifications
	}
	return map[string]any{
		"alias":         info.Alias,
		"color":         info.Color,
		"pubkey":        info.IdentityPubkey,
		"network":       network,
		"block_height":  info.BlockHeight,
		"block_hash":    info.BlockHash,
		"methods":       methods,
		"notifications": notif,
		"extensions":    Extensions,
	}, nil
}

func (s *Service) getBalance(ctx context.Context, id *store.Identity, conn *store.Connection) (any, error) {
	// Each identity is a wallet of its own: its balance is its ledger —
	// received minus sent, plus operator adjustments — never the node's
	// channel balance, and not narrowed by the connection's budget either:
	// an app always sees the balance even when its budget makes part of it
	// unspendable. A negative position (operator debit) reads as zero.
	bal, err := s.core.Balance(id.ID)
	if err != nil {
		return nil, fail(ErrInternal, "ledger unavailable")
	}
	avail := bal.Available
	if avail < 0 {
		avail = 0
	}
	return map[string]any{"balance": avail}, nil
}

func (s *Service) payInvoice(ctx context.Context, id *store.Identity, conn *store.Connection, raw json.RawMessage) (any, error) {
	var p struct {
		Invoice     string          `json:"invoice"`
		Amount      int64           `json:"amount"`
		Description string          `json:"description"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || strings.TrimSpace(p.Invoice) == "" {
		return nil, fail(ErrOther, "invoice is required")
	}
	if !s.spending() {
		return nil, fail(ErrRestricted, "sending is not enabled on this wallet service")
	}
	meta := paymentMetadata(p.Metadata, p.Description)
	// What the app attached, without its content: when a wallet shows an
	// outgoing zap as "to Unknown", this line says whether the app ever
	// told us who it was for.
	s.log.Info("nwc: pay_invoice", "identity", id.Name, "connection", conn.Label,
		"app_sent_metadata", len(p.Metadata) > 0 && string(p.Metadata) != "null", "app_sent_description", p.Description != "", "recipient_known", strings.Contains(meta, `"nostr"`))
	pay, err := s.core.PayInvoice(ctx, id, conn, p.Invoice, p.Amount, meta)
	if err != nil {
		var eb *core.ErrBudget
		var ef *core.ErrPaymentFailed
		var ei *core.ErrInsufficientBalance
		switch {
		case errors.Is(err, core.ErrSendingDisabled):
			return nil, fail(ErrRestricted, "sending is not enabled on this wallet service")
		case errors.Is(err, core.ErrSelfPayDisabled):
			return nil, fail(ErrOther, err.Error())
		case errors.Is(err, core.ErrPaymentPending):
			// NIP-47 has no "pending" result. PAYMENT_FAILED would be a lie
			// the wallet might act on (by paying again some other way), so
			// this is OTHER with the explanation; a payment_sent
			// notification follows if it settles.
			return nil, fail(ErrOther, err.Error())
		case errors.As(err, &ei):
			return nil, fail(ErrInsufficient, ei.Error())
		case errors.As(err, &eb):
			return nil, fail(ErrQuota, eb.Msg)
		case errors.As(err, &ef):
			if strings.Contains(ef.Reason, "guard:") {
				return nil, fail(ErrQuota, ef.Reason)
			}
			if strings.Contains(strings.ToUpper(ef.Reason), "INSUFFICIENT") {
				return nil, fail(ErrInsufficient, ef.Reason)
			}
			return nil, fail("PAYMENT_FAILED", ef.Reason)
		default:
			return nil, fail(ErrOther, err.Error())
		}
	}
	if pay != nil {
		go s.paymentSent(pay)
	}
	return map[string]any{"preimage": s.core.Preimage(pay.PreimageEnc), "fees_paid": pay.FeeMsat}, nil
}

// metadataObject returns an app's `metadata` as compact JSON if it is a
// non-empty JSON object of at most core.MaxMetadata characters, and ""
// otherwise (NWC-06: larger metadata must be dropped).
func metadataObject(meta json.RawMessage) string {
	if len(meta) == 0 {
		return ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(meta, &obj) != nil || len(obj) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if json.Compact(&buf, meta) != nil || buf.Len() > core.MaxMetadata {
		return ""
	}
	return buf.String()
}

// fitMetadata applies the same limit to metadata this service assembles for
// a transaction. A zap request alone may be nearly the whole allowance, so
// when the object is too large the request goes first and whatever smaller
// facts remain (comment, payer data) are kept; if that is still too large
// there is no metadata.
func fitMetadata(meta map[string]any) map[string]any {
	size := func() int { b, _ := json.Marshal(meta); return len(b) }
	if len(meta) == 0 {
		return nil
	}
	if size() <= core.MaxMetadata {
		return meta
	}
	if _, ok := meta["nostr"]; ok {
		delete(meta, "nostr")
		if len(meta) > 0 && size() <= core.MaxMetadata {
			return meta
		}
	}
	return nil
}

// paymentMetadata is what to keep of the note a paying app attaches to
// pay_invoice, as a compact JSON object, or "" for nothing.
//
// NIP-47 gives pay_invoice an optional `metadata` object, and a zapping app
// puts the kind-9734 zap request in it under "nostr". That request is the
// only thing that says who an outgoing payment was for (the invoice names a
// node, not a person), and it is what a wallet reads back from
// list_transactions to show a name instead of "Unknown". Damus also sends
// the request as a JSON string in `description`; that is used when there is
// no metadata.
//
// It is the app's own claim and is not checked against the invoice. It is
// shown only to apps connected to the same identity. Anything that is not a
// JSON object, or is larger than core.MaxMetadata, is dropped and
// the payment goes ahead without it.
func paymentMetadata(meta json.RawMessage, description string) string {
	if m := metadataObject(meta); m != "" {
		return m
	}
	if d := strings.TrimSpace(description); len(d) > 0 && len(d) <= core.MaxMetadata-len(`{"nostr":}`) && strings.HasPrefix(d, "{") {
		var ev struct {
			Kind   int    `json:"kind"`
			PubKey string `json:"pubkey"`
		}
		if json.Unmarshal([]byte(d), &ev) == nil && ev.Kind == 9734 && ev.PubKey != "" {
			var buf bytes.Buffer
			if json.Compact(&buf, []byte(d)) == nil {
				return `{"nostr":` + buf.String() + `}`
			}
		}
	}
	return ""
}

// paymentTransaction renders an outgoing payment as a NIP-47 transaction.
func (s *Service) paymentTransaction(p *store.Payment) map[string]any {
	state := "pending"
	switch p.State {
	case store.PaymentSettled:
		state = "settled"
	case store.PaymentFailed:
		state = "failed"
	}
	tx := map[string]any{
		"type":         "outgoing",
		"state":        state,
		"invoice":      p.Bolt11,
		"description":  p.Description,
		"payment_hash": p.PaymentHash,
		"amount":       p.AmountMsat,
		"fees_paid":    p.FeeMsat,
		"created_at":   p.CreatedAt.Unix(),
	}
	if p.State == store.PaymentSettled {
		tx["settled_at"] = p.SettledAt.Unix()
		if pre := s.core.Preimage(p.PreimageEnc); pre != "" {
			tx["preimage"] = pre
		}
	}
	meta := map[string]any{}
	if p.Metadata != "" {
		_ = json.Unmarshal([]byte(p.Metadata), &meta)
	}
	if p.Internal {
		meta["internal"] = true
		// The app did not say what this was for, but the invoice is this
		// node's own and its record does: a zap invoice carries the request
		// that names the recipient. (That request is published in the zap
		// receipt anyway; nothing private crosses from payee to payer.)
		if _, ok := meta["nostr"]; !ok {
			if inv, err := s.core.Store().GetInvoice(p.PaymentHash); err == nil && inv.ZapRequest != "" {
				var zr any
				if json.Unmarshal([]byte(inv.ZapRequest), &zr) == nil {
					meta["nostr"] = zr
				}
			}
		}
	}
	if meta = fitMetadata(meta); meta != nil {
		tx["metadata"] = meta
	}
	return tx
}

// PaymentSettled is core telling us a payment resolved after its request
// had already been answered.
func (s *Service) PaymentSettled(p *store.Payment) { go s.paymentSent(p) }

// paymentSent notifies the connection that paid.
func (s *Service) paymentSent(p *store.Payment) {
	id, err := s.core.Store().GetIdentity(p.IdentityID)
	if err != nil {
		return
	}
	conn, err := s.core.Store().GetConnection(p.ConnectionID)
	if err != nil || !conn.Notify {
		return
	}
	body, _ := json.Marshal(map[string]any{"notification_type": "payment_sent", "notification": s.paymentTransaction(p)})
	s.notify(id, conn, body)
}

func (s *Service) makeInvoice(ctx context.Context, id *store.Identity, conn *store.Connection, raw json.RawMessage) (any, error) {
	var p struct {
		Amount          int64           `json:"amount"`
		Description     string          `json:"description"`
		DescriptionHash string          `json:"description_hash"`
		Expiry          int64           `json:"expiry"`
		Metadata        json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Amount <= 0 {
		return nil, fail(ErrOther, "amount (msat) is required")
	}
	exp := time.Duration(p.Expiry) * time.Second
	if exp <= 0 || exp > 7*24*time.Hour {
		exp = 0
	}
	inv, err := s.core.CreateInvoice(ctx, core.CreateInvoiceParams{
		Identity:     id.Name,
		AmountMsat:   p.Amount,
		Description:  p.Description,
		DescHashHex:  p.DescriptionHash,
		Source:       store.SourceNWC,
		ConnectionID: conn.ID,
		Expiry:       exp,
		Metadata:     metadataObject(p.Metadata),
	})
	if err != nil {
		return nil, fail(ErrOther, err.Error())
	}
	return s.transaction(inv), nil
}

// lookupInvoice answers lookup_invoice: one transaction of this identity, by
// payment hash or by BOLT11 string. NIP-47 uses the one method for both
// directions, and a wallet asks it about a payment it just sent as readily
// as about an invoice it made. (The first version only knew invoices this
// service had issued, so a sent payment came back NOT_FOUND.)
//
// Only this identity's records are ever returned; another identity's
// payment hash is NOT_FOUND, the same answer as one that does not exist.
func (s *Service) lookupInvoice(ctx context.Context, id *store.Identity, conn *store.Connection, raw json.RawMessage) (any, error) {
	var p struct {
		PaymentHash string `json:"payment_hash"`
		Invoice     string `json:"invoice"`
	}
	_ = json.Unmarshal(raw, &p)
	st := s.core.Store()
	var inv *store.Invoice
	var pay *store.Payment
	switch {
	case p.PaymentHash != "":
		hash := strings.ToLower(strings.TrimSpace(p.PaymentHash))
		if i, err := st.GetInvoice(hash); err == nil && i.IdentityID == id.ID {
			inv = i
		}
		if o, err := st.GetPayment(hash); err == nil && o.IdentityID == id.ID {
			pay = o
		}
	case p.Invoice != "":
		// Stored invoices are lower case without a "lightning:" prefix;
		// compare like with like. The search covers the same recent
		// history list_transactions does.
		want, err := lnd.NormalizeBolt11(p.Invoice)
		if err != nil {
			return nil, fail(ErrNotFound, "no such invoice or payment on this wallet")
		}
		if list, err := st.ListInvoices(id.ID, 0, 500); err == nil {
			for _, i := range list {
				if strings.EqualFold(i.Bolt11, want) {
					inv = i
					break
				}
			}
		}
		if list, err := st.ListPayments(id.ID, 0, 500); err == nil {
			for _, o := range list {
				if strings.EqualFold(o.Bolt11, want) {
					pay = o
					break
				}
			}
		}
	default:
		return nil, fail(ErrOther, "payment_hash or invoice is required")
	}
	// An app that made an invoice asks this until it is paid. Ask LND about
	// one that is still open, so the answer does not wait on the stream.
	if inv != nil && inv.State == store.InvoiceOpen {
		s.core.RefreshInvoice(ctx, inv.PaymentHash)
		if cur, err := st.GetInvoice(inv.PaymentHash); err == nil {
			inv = cur
		}
	}
	switch {
	case inv != nil && pay != nil:
		// An identity that paid its own invoice (a self-zap) has both
		// sides under one payment hash. Answer with the side this
		// connection took part in: the payment if it sent it and did not
		// also make the invoice, otherwise the invoice.
		if pay.ConnectionID == conn.ID && inv.ConnectionID != conn.ID {
			return s.paymentTransaction(pay), nil
		}
		return s.transaction(inv), nil
	case inv != nil:
		return s.transaction(inv), nil
	case pay != nil:
		return s.paymentTransaction(pay), nil
	}
	return nil, fail(ErrNotFound, "no such invoice or payment on this wallet")
}

func (s *Service) listTransactions(ctx context.Context, id *store.Identity, raw json.RawMessage) (any, error) {
	var p struct {
		From   int64  `json:"from"`
		Until  int64  `json:"until"`
		Limit  int    `json:"limit"`
		Offset int    `json:"offset"`
		Unpaid bool   `json:"unpaid"`
		Type   string `json:"type"`
	}
	_ = json.Unmarshal(raw, &p)
	if p.Limit <= 0 || p.Limit > 100 {
		p.Limit = 50
	}
	type row struct {
		at int64
		tx map[string]any
	}
	var rows []row
	truncated := false
	if p.Type != "outgoing" {
		list, err := s.core.Store().ListInvoices(id.ID, 0, 500)
		if err != nil {
			return nil, fail(ErrInternal, "store error")
		}
		truncated = truncated || len(list) >= 500
		for _, inv := range list {
			if !p.Unpaid && inv.State != store.InvoiceSettled {
				continue
			}
			rows = append(rows, row{inv.CreatedAt.Unix(), s.transaction(inv)})
		}
	}
	if p.Type != "incoming" {
		list, err := s.core.Store().ListPayments(id.ID, 0, 500)
		if err != nil {
			return nil, fail(ErrInternal, "store error")
		}
		truncated = truncated || len(list) >= 500
		for _, pay := range list {
			if !p.Unpaid && pay.State != store.PaymentSettled {
				continue
			}
			rows = append(rows, row{pay.CreatedAt.Unix(), s.paymentTransaction(pay)})
		}
	}
	// Operator adjustments are part of the history too, as LNbits reports a
	// top-up: a settled entry with no invoice, so the list sums to the balance
	// the app shows. `unpaid` adds unpaid invoices to the list (NWC-05); it
	// takes nothing away, so adjustments are listed with it and without.
	{
		list, err := s.core.Store().ListAdjustments(id.ID, 0, 500)
		if err != nil {
			return nil, fail(ErrInternal, "store error")
		}
		truncated = truncated || len(list) >= 500
		for _, a := range list {
			if (p.Type == "incoming" && a.AmountMsat < 0) || (p.Type == "outgoing" && a.AmountMsat > 0) {
				continue
			}
			rows = append(rows, row{a.CreatedAt.Unix(), adjustmentTransaction(a)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
	out := []map[string]any{}
	skipped, matched := 0, 0
	for _, r := range rows {
		if p.From > 0 && r.at < p.From {
			continue
		}
		if p.Until > 0 && r.at > p.Until {
			continue
		}
		matched++
		if skipped < p.Offset {
			skipped++
			continue
		}
		if len(out) < p.Limit {
			out = append(out, r.tx)
		}
	}
	out, full, slim, bare := fitTransactions(out, s.resultBudget(id))
	if slim+bare > 0 || len(out) < full {
		s.log.Info("nwc: list_transactions trimmed to fit one event", "identity", id.Name, "matched", full, "sent", len(out), "without_invoice", slim, "without_metadata", bare)
	}
	res := map[string]any{"transactions": out}
	// total_count (optional in NWC-05) is how many transactions match the
	// filters before paging. It is given only when it is exact: once any of
	// the three sources is at its read limit there may be older records
	// that were not counted.
	if !truncated {
		res["total_count"] = matched
	}
	return res, nil
}

// How large a reply may be before encryption, in bytes of JSON.
//
// A reply is one Nostr event, and relays bound event size: the embedded
// relay at relay.MaxServiceEventBytes, public ones commonly at 64 KiB.
// NIP-44 pads the plaintext (to 65,536 at most, its hard limit being
// 65,535 bytes) and base64 adds a third, so 60,000 bytes becomes about
// 87 KiB of content and 40,000 about 55 KiB.
const (
	MaxResultBytes        = 60_000 // on the embedded relay
	MaxResultBytesForeign = 40_000 // on an operator-chosen relay, whose limit is unknown
	resultEnvelopeBytes   = 256    // result_type, error and braces around the list
)

// resultBudget is the reply size that fits the relay this identity's wallet
// traffic runs on.
func (s *Service) resultBudget(id *store.Identity) int {
	if s.core.NWCRelayFor(id) == s.core.NWCRelayFor(&store.Identity{}) {
		return MaxResultBytes
	}
	return MaxResultBytesForeign
}

// fitTransactions makes a transaction list (newest first) fit budget bytes
// of JSON, giving up the least useful data first:
//
//  1. The list as it is, if it fits.
//  2. Without the BOLT11 string of entries that are no longer payable. It
//     is the largest field after a zap request and a history view has no
//     use for it; payment hash, preimage, amounts and times stay.
//  3. Without metadata on the oldest entries, one at a time. Metadata is
//     where a zap's kind-9734 request lives (up to 4 KiB each), which is
//     what a wallet shows the zapper's name from, so the newest keep it.
//  4. Without the oldest entries altogether.
//
// A wallet asks for a page (Damus: the latest 50, once) and shows whatever
// comes back, so a shorter or plainer page is a full answer; an event the
// relay refuses is no answer at all. It returns the list, how many entries
// went in, and how many lost their invoice and their metadata.
func fitTransactions(txs []map[string]any, budget int) (out []map[string]any, full, slim, bare int) {
	full = len(txs)
	budget -= resultEnvelopeBytes
	size := func(tx map[string]any) int {
		b, _ := json.Marshal(tx)
		return len(b) + 1 // and its comma
	}
	sizes := make([]int, len(txs))
	total := 0
	for i, tx := range txs {
		sizes[i] = size(tx)
		total += sizes[i]
	}
	if total <= budget {
		return txs, full, 0, 0
	}
	// Entries are shared with nobody, but copy before editing all the same.
	edit := func(i int, key string) {
		c := make(map[string]any, len(txs[i]))
		for k, v := range txs[i] {
			if k != key {
				c[k] = v
			}
		}
		txs[i] = c
		total -= sizes[i]
		sizes[i] = size(c)
		total += sizes[i]
	}
	for i, tx := range txs {
		if _, ok := tx["invoice"]; ok && tx["state"] != "pending" {
			edit(i, "invoice")
			slim++
		}
	}
	for i := len(txs) - 1; i >= 0 && total > budget; i-- {
		if _, ok := txs[i]["metadata"]; ok {
			edit(i, "metadata")
			bare++
		}
	}
	for len(txs) > 0 && total > budget {
		total -= sizes[len(txs)-1]
		txs = txs[:len(txs)-1]
	}
	return txs, full, slim, bare
}

// adjustmentTransaction renders an operator credit or debit as a NIP-47
// transaction. There is no invoice and no preimage; the payment hash is a
// synthetic, stable value derived from the adjustment id so apps that key
// their history on it stay consistent across calls.
func adjustmentTransaction(a *store.Adjustment) map[string]any {
	typ, amt := "incoming", a.AmountMsat
	if amt < 0 {
		typ, amt = "outgoing", -amt
	}
	desc := a.Note
	if desc == "" {
		if typ == "incoming" {
			desc = "Balance credit"
		} else {
			desc = "Balance debit"
		}
	}
	h := sha256.Sum256([]byte("adjustment:" + a.ID))
	return map[string]any{
		"type":         typ,
		"state":        "settled",
		"description":  desc,
		"payment_hash": hex.EncodeToString(h[:]),
		"amount":       amt,
		"fees_paid":    int64(0),
		"created_at":   a.CreatedAt.Unix(),
		"settled_at":   a.CreatedAt.Unix(),
		"metadata":     map[string]any{"adjustment": true},
	}
}

func (s *Service) transaction(inv *store.Invoice) map[string]any {
	// The states NIP-47 gives an invoice: pending, settled, expired.
	// ("failed" is for payments.) LND cancels an invoice when it expires,
	// so a canceled one is an expired one here; and an invoice that is
	// still open in the ledger but past its expiry is expired whether or
	// not the node has said so yet.
	state := "pending"
	switch inv.State {
	case store.InvoiceSettled:
		state = "settled"
	case store.InvoiceExpired, store.InvoiceCanceled:
		state = "expired"
	default:
		if !inv.ExpiresAt.IsZero() && time.Now().After(inv.ExpiresAt) {
			state = "expired"
		}
	}
	tx := map[string]any{
		"type":             "incoming",
		"state":            state,
		"invoice":          inv.Bolt11,
		"description":      inv.Description,
		"description_hash": inv.DescriptionHash,
		"payment_hash":     inv.PaymentHash,
		"amount":           inv.AmountMsat,
		"fees_paid":        0,
		"created_at":       inv.CreatedAt.Unix(),
		"expires_at":       inv.ExpiresAt.Unix(),
	}
	if inv.State == store.InvoiceSettled {
		tx["settled_at"] = inv.SettledAt.Unix()
		if len(inv.PreimageEnc) > 0 {
			if pre, err := s.core.Sealer().Open(inv.PreimageEnc); err == nil {
				tx["preimage"] = hex.EncodeToString(pre)
			}
		}
	}
	// What the app attached when it made the invoice, then the facts this
	// service recorded itself, which win over an app's key of the same name.
	meta := map[string]any{}
	if inv.Metadata != "" {
		_ = json.Unmarshal([]byte(inv.Metadata), &meta)
	}
	if inv.Comment != "" {
		meta["comment"] = inv.Comment
	}
	if inv.ZapRequest != "" {
		var zr any
		if json.Unmarshal([]byte(inv.ZapRequest), &zr) == nil {
			meta["nostr"] = zr
		}
	}
	if inv.PayerData != "" {
		var pd any
		if json.Unmarshal([]byte(inv.PayerData), &pd) == nil {
			meta["payer_data"] = pd
		}
	}
	if meta = fitMetadata(meta); meta != nil {
		tx["metadata"] = meta
	}
	return tx
}

// InvoiceSettled sends payment_received to every connection of the identity
// that asked for notifications.
func (s *Service) InvoiceSettled(inv *store.Invoice) {
	id, err := s.core.Store().GetIdentity(inv.IdentityID)
	if err != nil {
		return
	}
	conns, err := s.core.Store().ListConnections(id.ID)
	if err != nil {
		return
	}
	body, _ := json.Marshal(map[string]any{"notification_type": "payment_received", "notification": s.transaction(inv)})
	now := time.Now()
	for _, c := range conns {
		if c.Active(now) && c.Notify {
			s.notify(id, c, body)
		}
	}
}

// notify publishes a NIP-47 notification in both encryptions, since a client
// subscribes to the kind matching the one it speaks.
func (s *Service) notify(id *store.Identity, c *store.Connection, body []byte) {
	svcSK, err := s.core.NWCSecret(id)
	if err != nil {
		return
	}
	for _, scheme := range []string{"nip44_v2", "nip04"} {
		content, err := encrypt(scheme, string(body), c.ClientPubkey, svcSK)
		if err != nil {
			continue
		}
		kind := KindNotification
		if scheme == "nip04" {
			kind = KindNotify04
		}
		ev := &nostr.Event{Kind: kind, CreatedAt: nostr.Now(), Content: content, Tags: nostr.Tags{{"p", c.ClientPubkey}}}
		if scheme == "nip44_v2" {
			ev.Tags = append(ev.Tags, nostr.Tag{"encryption", "nip44_v2"})
		}
		if err := ev.Sign(svcSK); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		s.core.Publisher().Publish(ctx, s.relaysFor(id), ev)
		cancel()
	}
}

// publishInfoAll keeps every identity's kind-13194 info event current on
// its relay for as long as ctx lives. It retries with backoff until each
// relay has accepted the event (at startup the embedded relay comes up
// after core, so the first attempt usually fails), and republishes whenever
// the advertised method set changes — i.e. when sending is enabled or
// disabled, since pay_invoice is advertised only while a spend credential
// exists. On top of that it republishes everything every InfoRepublish, as
// LNbits's nwcprovider does every minute: a relay can drop a stored event
// without closing the socket, and a replaceable event costs nothing to
// resend. Ten minutes rather than one because a wallet reads the info event
// when it pairs, so a dropped one only matters until the next republish.
func (s *Service) publishInfoAll(ctx context.Context) {
	delay := 2 * time.Second
	published := map[string]bool{} // identity id -> info event accepted somewhere
	last := s.spending()
	nextFull := time.Now().Add(InfoRepublish)
	for ctx.Err() == nil {
		if sp := s.spending(); sp != last {
			s.log.Info("nwc: sending state changed; republishing info events", "sending", sp)
			last = sp
			published = map[string]bool{}
			delay = 2 * time.Second
		} else if time.Now().After(nextFull) {
			published = map[string]bool{}
			delay = 2 * time.Second
		}
		if len(published) == 0 {
			nextFull = time.Now().Add(InfoRepublish)
		}
		ids, err := s.core.Store().ListIdentities()
		if err == nil {
			for _, id := range ids {
				if id.Disabled || published[id.ID] {
					continue
				}
				if err := s.PublishInfo(ctx, id); err != nil {
					s.log.Warn("nwc: info event not accepted yet", "identity", id.Name, "err", err, "retry_in", delay)
					continue
				}
				published[id.ID] = true
			}
		}
		pending := false
		for _, id := range ids {
			if !id.Disabled && !published[id.ID] {
				pending = true
			}
		}
		wait := 10 * time.Second // idle poll for a sending-state change
		if pending {
			wait = delay
			if delay < time.Minute {
				delay *= 2
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// PublishInfo publishes an identity's NIP-47 info event.
func (s *Service) PublishInfo(ctx context.Context, id *store.Identity) error {
	sk, err := s.core.NWCSecret(id)
	if err != nil {
		return err
	}
	methods := append([]string{}, ReadMethods...)
	if s.spending() {
		methods = append(methods, SpendMethods...)
	}
	ev := &nostr.Event{
		Kind:      KindInfo,
		CreatedAt: nostr.Now(),
		Content:   strings.Join(methods, " "),
		Tags: nostr.Tags{
			{"notifications", strings.Join(Notifications, " ")},
			{"encryption", strings.Join(Encryptions, " ")},
			{"extensions", strings.Join(Extensions, " ")},
		},
	}
	if err := ev.Sign(sk); err != nil {
		return err
	}
	ok := s.core.Publisher().Publish(ctx, s.relaysFor(id), ev)
	if len(ok) == 0 {
		return fmt.Errorf("no relay accepted the info event")
	}
	return nil
}

// ConnectionURI renders the nostr+walletconnect:// URI for a fresh client
// secret; the caller shows it once and never stores the secret.
func ConnectionURI(servicePubkey, clientSecret, relayURL, lud16 string) string {
	u := "nostr+walletconnect://" + servicePubkey + "?relay=" + urlEscape(relayURL) + "&secret=" + clientSecret
	if lud16 != "" {
		u += "&lud16=" + urlEscape(lud16)
	}
	return u
}

func urlEscape(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "?", "%3F", "#", "%23", " ", "%20", "/", "%2F", ":", "%3A", "@", "%40")
	return r.Replace(s)
}

// HandleForTest feeds one raw event through the same path the subscription
// uses (signature, NIP-40, pairing, decrypt, dispatch, respond).
func (s *Service) HandleForTest(ctx context.Context, ev *nostr.Event, relayURL string) {
	s.handle(ctx, ev, relayURL)
}

// DispatchForTest runs one method as if it had arrived over the relay and
// returns the response body (the JSON the client would decrypt). Tests use it
// to exercise the money paths without a relay in the loop.
func (s *Service) DispatchForTest(ctx context.Context, id *store.Identity, conn *store.Connection, method string, params json.RawMessage) []byte {
	res := response{ResultType: method}
	result, err := s.dispatch(ctx, id, conn, request{Method: method, Params: params})
	if err != nil {
		var ne *nwcError
		if errors.As(err, &ne) {
			res.Error = ne
		} else {
			res.Error = &nwcError{ErrInternal, err.Error()}
		}
	} else {
		res.Result = result
	}
	b, _ := json.Marshal(res)
	return b
}

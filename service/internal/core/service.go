// Package core is the privileged-but-bounded process: it owns the identity
// table and keys, creates invoices with the receive credential the guard
// baked, publishes zap receipts and NWC traffic, and serves the admin UI on
// the LAN-only interface. It never sees admin.macaroon.
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/identity"
	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// Config is what core is told at start.
type Config struct {
	DataDir        string // /core
	CredentialsDir string // /credentials (read-only)
	IdentitiesDir  string // /identities (edge reads it read-only)
	GuardSocket    string
	EdgeSocket     string
	EdgeUIDs       []uint32
	LNDRestURL     string
	LNDCAFile      string
	BaseURL        string // https://domain, from the primary-domain action; "" until set
	RelayURL       string // wss://domain/relay
	LocalRelayURL  string // ws://127.0.0.1:8080/relay (same network namespace)
	DefaultRelays  []string
	InvoiceExpiry  time.Duration
	// InvoicePrivate adds route hints for private channels to every invoice
	// (LND's `private`). On by default: a node whose channels are all
	// unannounced is otherwise unpayable. Operator-configurable later (see
	// design §12, "Lightning settings").
	InvoicePrivate bool
	Log            *slog.Logger
}

// Service is the running core.
type Service struct {
	cfg    Config
	log    *slog.Logger
	store  *store.Store
	sealer *store.Sealer
	guard  *ipc.Client
	pub    *Publisher

	lndMu sync.Mutex

	sendingMu sync.Mutex
	sending   map[string]bool // payment hashes with a live PayInvoice

	lnd  *lnd.Client
	node *lnd.Info

	docMu sync.Mutex
	nwc   NWCNotifier // set by the NWC service to receive settle notifications

	// The settlement safety net (invoices.go).
	watchMu       sync.Mutex
	restartStream context.CancelFunc // ends the current invoice stream so it is reopened
	refreshEach   *httpx.Limiter     // per invoice
	refreshAll    *httpx.Limiter     // all invoices together
}

// NWCNotifier is what the NWC service exposes to core for settle events and
// configuration changes.
type NWCNotifier interface {
	InvoiceSettled(inv *store.Invoice)
	// PaymentSettled is called when a payment resolves after the wallet's
	// request was already answered ("still in flight").
	PaymentSettled(p *store.Payment)
	IdentitiesChanged()
}

// New opens the store and prepares the service.
func New(cfg Config) (*Service, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.InvoiceExpiry <= 0 {
		cfg.InvoiceExpiry = 15 * time.Minute
	}
	for _, d := range []string{cfg.DataDir, cfg.IdentitiesDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "core.db"))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	sealer, err := store.LoadOrCreateMasterKey(filepath.Join(cfg.DataDir, "master.key"))
	if err != nil {
		st.Close()
		return nil, err
	}
	s := &Service{
		cfg:    cfg,
		log:    cfg.Log,
		store:  st,
		sealer: sealer,
		guard:  &ipc.Client{Path: cfg.GuardSocket, Timeout: 5 * time.Second},
		pub:    NewPublisher(cfg.Log),

		refreshEach: httpx.NewLimiter(refreshEachPerMinute, 2),
		refreshAll:  httpx.NewLimiter(refreshPerMinute, 20),
	}
	return s, nil
}

// Close releases the store.
func (s *Service) Close() { s.store.Close() }

// Store exposes the store to the admin and NWC packages.
func (s *Service) Store() *store.Store { return s.store }

// Sealer exposes the sealer.
func (s *Service) Sealer() *store.Sealer { return s.sealer }

// Publisher exposes the relay publisher.
func (s *Service) Publisher() *Publisher { return s.pub }

// Config exposes the configuration.
func (s *Service) Config() Config { return s.cfg }

// SetNWC registers the NWC service for settle notifications.
func (s *Service) SetNWC(n NWCNotifier) { s.nwc = n }

// Domain is the host part of every address, or "" until the operator picked a
// primary domain.
func (s *Service) Domain() string {
	u, err := url.Parse(s.cfg.BaseURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ---- LND ----

// LND returns a client holding the current receive credential, reloading the
// macaroon file on every call so a renewal by the guard is picked up at once.
func (s *Service) LND() (*lnd.Client, error) {
	s.lndMu.Lock()
	defer s.lndMu.Unlock()
	path := filepath.Join(s.cfg.CredentialsDir, "recv.macaroon")
	if s.lnd == nil {
		c, err := lnd.New(s.cfg.LNDRestURL, s.cfg.LNDCAFile, "")
		if err != nil {
			return nil, err
		}
		s.lnd = c
	}
	if err := s.lnd.LoadMacaroon(path); err != nil {
		return nil, fmt.Errorf("receive credential not available yet: %w", err)
	}
	return s.lnd, nil
}

// NodeInfo returns the cached GetInfo, refreshing it when stale.
func (s *Service) NodeInfo(ctx context.Context) (*lnd.Info, error) {
	s.lndMu.Lock()
	cached := s.node
	s.lndMu.Unlock()
	if cached != nil {
		return cached, nil
	}
	c, err := s.LND()
	if err != nil {
		return nil, err
	}
	info, err := c.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	s.lndMu.Lock()
	s.node = info
	s.lndMu.Unlock()
	return info, nil
}

func (s *Service) forgetNode() {
	s.lndMu.Lock()
	s.node = nil
	s.lndMu.Unlock()
}

// GuardStatus asks the guard how it is doing.
func (s *Service) GuardStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.guard.Call(ctx, "status", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RequestRebake asks the guard to bake fresh credentials now.
func (s *Service) RequestRebake(ctx context.Context) error {
	return s.guard.Call(ctx, "rebake", nil, nil)
}

// ---- identities ----

// NewIdentity creates an identity with fresh service keys.
func (s *Service) NewIdentity(name, displayName, userPubkey string, nip05 bool, minMsat, maxMsat int64, comment int, relays []string, nwcRelay string) (*store.Identity, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !identity.ValidName(name) {
		return nil, errors.New("name may contain only a-z, 0-9, dot, underscore and dash (or be `_`)")
	}
	if userPubkey != "" && !nostr.IsValidPublicKey(userPubkey) {
		return nil, errors.New("Nostr pubkey must be 64 hex characters (use the hex form, not npub)")
	}
	nwcRelay = strings.TrimSpace(nwcRelay)
	if nwcRelay != "" && len(cleanRelays([]string{nwcRelay})) != 1 {
		return nil, errors.New("the NWC relay must be a ws:// or wss:// URL")
	}
	zapSK := nostr.GeneratePrivateKey()
	zapPK, _ := nostr.GetPublicKey(zapSK)
	nwcSK := nostr.GeneratePrivateKey()
	nwcPK, _ := nostr.GetPublicKey(nwcSK)
	zapEnc, err := s.sealer.Seal([]byte(zapSK))
	if err != nil {
		return nil, err
	}
	nwcEnc, err := s.sealer.Seal([]byte(nwcSK))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	id := &store.Identity{
		ID:              newID(),
		Name:            name,
		DisplayName:     strings.TrimSpace(displayName),
		UserPubkey:      strings.ToLower(userPubkey),
		NIP05Enabled:    nip05 && userPubkey != "",
		ZapPubkey:       zapPK,
		ZapSecretEnc:    zapEnc,
		NWCPubkey:       nwcPK,
		NWCSecretEnc:    nwcEnc,
		MinSendableMsat: minMsat,
		MaxSendableMsat: maxMsat,
		CommentAllowed:  comment,
		Relays:          cleanRelays(relays),
		NWCRelay:        nwcRelay,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.store.PutIdentity(id); err != nil {
		return nil, err
	}
	s.PublishIdentities()
	return id, nil
}

// UpdateIdentity stores an edited identity and republishes the document.
func (s *Service) UpdateIdentity(id *store.Identity) error {
	if id.UserPubkey != "" && !nostr.IsValidPublicKey(id.UserPubkey) {
		return errors.New("Nostr pubkey must be 64 hex characters")
	}
	if id.UserPubkey == "" {
		id.NIP05Enabled = false
	}
	id.Relays = cleanRelays(id.Relays)
	if id.NWCRelay != "" {
		if r := cleanRelays([]string{id.NWCRelay}); len(r) == 1 {
			id.NWCRelay = r[0]
		} else {
			return errors.New("the NWC relay must be a ws:// or wss:// URL")
		}
	}
	id.UpdatedAt = time.Now().UTC()
	if err := s.store.PutIdentity(id); err != nil {
		return err
	}
	s.PublishIdentities()
	return nil
}

// DeleteIdentity removes an identity (its connections are revoked).
func (s *Service) DeleteIdentity(id string) error {
	if err := s.store.DeleteIdentity(id); err != nil {
		return err
	}
	s.PublishIdentities()
	return nil
}

// RotateZapKey replaces an identity's zap-signing key.
func (s *Service) RotateZapKey(id *store.Identity) error {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	enc, err := s.sealer.Seal([]byte(sk))
	if err != nil {
		return err
	}
	id.ZapSecretEnc, id.ZapPubkey = enc, pk
	return s.UpdateIdentity(id)
}

// RotateNWCKey replaces an identity's wallet-service key and revokes every
// connection, since each URI named the old key.
func (s *Service) RotateNWCKey(id *store.Identity) error {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	enc, err := s.sealer.Seal([]byte(sk))
	if err != nil {
		return err
	}
	conns, err := s.store.ListConnections(id.ID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, c := range conns {
		if c.RevokedAt == nil {
			c.RevokedAt = &now
			if err := s.store.PutConnection(c); err != nil {
				return err
			}
		}
	}
	id.NWCSecretEnc, id.NWCPubkey = enc, pk
	if err := s.UpdateIdentity(id); err != nil {
		return err
	}
	if s.nwc != nil {
		s.nwc.IdentitiesChanged()
	}
	return nil
}

// ZapSecret unseals an identity's zap key.
func (s *Service) ZapSecret(id *store.Identity) (string, error) {
	b, err := s.sealer.Open(id.ZapSecretEnc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NWCSecret unseals an identity's wallet-service key.
func (s *Service) NWCSecret(id *store.Identity) (string, error) {
	b, err := s.sealer.Open(id.NWCSecretEnc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NWCRelayFor is the public relay URL an identity's NWC runs on: its own
// override, else the embedded relay. Empty only while no domain is set.
func (s *Service) NWCRelayFor(id *store.Identity) string {
	if id.NWCRelay != "" {
		return id.NWCRelay
	}
	return s.cfg.RelayURL
}

// NWCDialRelaysFor is what core itself dials for an identity's NWC: the
// override if set, else the embedded relay over loopback plus any operator
// defaults.
func (s *Service) NWCDialRelaysFor(id *store.Identity) []string {
	if id.NWCRelay != "" {
		return s.DialRelays([]string{id.NWCRelay})
	}
	var out []string
	if s.cfg.LocalRelayURL != "" {
		out = append(out, s.cfg.LocalRelayURL)
	}
	return append(out, s.cfg.DefaultRelays...)
}

// MaxZapRelays bounds how many relays one zap request can make core dial.
const MaxZapRelays = 16

// relayHostPort is the host:port a relay URL is dialled at, or "".
func relayHostPort(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "wss", "https":
			port = "443"
		case "ws", "http":
			port = "80"
		default:
			return ""
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// TrustedDial reports whether hostport is a relay the operator configured:
// the embedded relay, the operator defaults, an identity's receipt relays or
// its NWC relay. Those may live on this box or this LAN. Every other
// destination — in practice, relays named by strangers in zap requests —
// must be a public address (httpx.RestrictOutbound enforces it).
func (s *Service) TrustedDial(hostport string) bool {
	hostport = strings.ToLower(hostport)
	match := func(relay string) bool { hp := relayHostPort(relay); return hp != "" && hp == hostport }
	if match(s.cfg.LocalRelayURL) {
		return true
	}
	for _, r := range s.cfg.DefaultRelays {
		if match(r) {
			return true
		}
	}
	ids, err := s.store.ListIdentities()
	if err != nil {
		return false
	}
	for _, id := range ids {
		if match(id.NWCRelay) {
			return true
		}
		for _, r := range id.Relays {
			if match(r) {
				return true
			}
		}
	}
	return false
}

// untrustedRelays cleans relay URLs that came from outside (a zap request):
// ws/wss only, a real host, no credentials, deduplicated, and no more than
// MaxZapRelays of them.
func untrustedRelays(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		u, err := url.Parse(strings.TrimSpace(r))
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Hostname() == "" || u.User != nil {
			continue
		}
		u.Fragment = ""
		clean := u.String()
		if seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
		if len(out) >= MaxZapRelays {
			break
		}
	}
	return out
}

// DialRelays maps the embedded relay's public URL to its loopback URL and
// dedupes: core must never dial its own relay by name (it would go out
// through the OS proxy and back in, and count as a second relay).
func (s *Service) DialRelays(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if s.cfg.LocalRelayURL != "" && s.cfg.RelayURL != "" && strings.TrimRight(r, "/") == strings.TrimRight(s.cfg.RelayURL, "/") {
			r = s.cfg.LocalRelayURL
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// RelaysFor is the receipt relay set for an identity: its own extras, the
// operator defaults and the embedded relay (public URL).
func (s *Service) RelaysFor(id *store.Identity) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	for _, r := range id.Relays {
		add(r)
	}
	for _, r := range s.cfg.DefaultRelays {
		add(r)
	}
	if s.cfg.RelayURL != "" {
		add(s.cfg.RelayURL)
	}
	return out
}

// PublishIdentities rewrites the edge document from the store.
func (s *Service) PublishIdentities() {
	s.docMu.Lock()
	defer s.docMu.Unlock()
	ids, err := s.store.ListIdentities()
	if err != nil {
		s.log.Error("list identities", "err", err)
		return
	}
	doc := &identity.Doc{
		Domain:   s.Domain(),
		BaseURL:  strings.TrimRight(s.cfg.BaseURL, "/"),
		RelayURL: s.cfg.RelayURL,
	}
	now := time.Now()
	for _, id := range ids {
		if id.Disabled {
			continue
		}
		doc.Identities = append(doc.Identities, identity.Entry{
			Name:           id.Name,
			DisplayName:    id.DisplayName,
			ZapPubkey:      id.ZapPubkey,
			NWCPubkey:      id.NWCPubkey,
			UserPubkey:     id.UserPubkey,
			NIP05:          id.NIP05Enabled,
			MinMsat:        id.MinSendableMsat,
			MaxMsat:        id.MaxSendableMsat,
			CommentAllowed: id.CommentAllowed,
			Relays:         id.Relays,
		})
		conns, err := s.store.ListConnections(id.ID)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if c.Active(now) {
				doc.NWCClients = append(doc.NWCClients, identity.NWCClient{ClientPubkey: c.ClientPubkey, ServicePubkey: id.NWCPubkey, Identity: id.Name})
			}
		}
	}
	if doc.Identities == nil {
		doc.Identities = []identity.Entry{}
	}
	if doc.NWCClients == nil {
		doc.NWCClients = []identity.NWCClient{}
	}
	if err := identity.Write(s.cfg.IdentitiesDir, doc); err != nil {
		s.log.Error("write identities document", "err", err)
	}
	if s.nwc != nil {
		s.nwc.IdentitiesChanged()
	}
}

func cleanRelays(in []string) []string {
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !strings.HasPrefix(r, "wss://") && !strings.HasPrefix(r, "ws://") {
			continue
		}
		out = append(out, r)
	}
	return out
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func statFile(p string) (int64, error) {
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// LowerCaps asks the guard to tighten the spending caps (never raise).
func (s *Service) LowerCaps(ctx context.Context, maxPaymentMsat, max24hMsat int64) (map[string]any, error) {
	var out map[string]any
	err := s.guard.Call(ctx, "lower_caps", map[string]int64{"max_payment_msat": maxPaymentMsat, "max_24h_msat": max24hMsat}, &out)
	return out, err
}

// DisableSending asks the guard to drop the latch and the spend credential.
func (s *Service) DisableSending(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := s.guard.Call(ctx, "disable_sending", nil, &out)
	return out, err
}

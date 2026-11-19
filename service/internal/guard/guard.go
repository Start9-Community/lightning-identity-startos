// Package guard is the credential broker. It is the only process that ever
// reads admin.macaroon; it bakes the narrow, short-lived credentials the core
// runs on, renews them before they expire, registers the RPC middleware that
// caps spending inside LND's request path, and answers status questions over a
// unix socket. It listens on no TCP port.
package guard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/macaroon"
)

// ReceiveMethods is the complete URI set the receive credential grants. It is
// what a Lightning Address, zap receipts, NWC's read-only methods and the
// health check need, and nothing else. URI-scoped on purpose: `invoices:write`
// would cover every invoice-mutating RPC. No ListInvoices/ListPayments and no
// ChannelBalance: histories and balances come from core's own per-identity
// ledger, so no NWC client can learn the node's.
var ReceiveMethods = []string{
	"/lnrpc.Lightning/GetInfo",
	"/lnrpc.Lightning/AddInvoice",
	"/lnrpc.Lightning/LookupInvoice",
	"/lnrpc.Lightning/SubscribeInvoices",
	// For self-pay: an internally settled invoice is cancelled on LND so it
	// cannot also be paid over Lightning. Cancel-only; it cannot settle or
	// create anything. (Added 2026-10-21; design §6.5.)
	"/invoicesrpc.Invoices/CancelInvoice",
}

// Credential lifetimes. Renewal runs well inside the validity window so a
// guard that misses one tick (LND locked, box asleep) still leaves a live
// credential behind.
const (
	Validity      = 24 * time.Hour
	RenewInterval = time.Hour
	RenewBefore   = 6 * time.Hour
)

// AuthPoll is how often the guard looks for a new authorization file. A
// variable so tests can shorten it.
var AuthPoll = 5 * time.Second

// Config is everything the guard is told at start.
type Config struct {
	LNDRestURL     string
	LNDGRPCAddress string // host:port of LND's gRPC over the bridge
	LNDCAFile      string
	AdminMacaroon  string // path to admin.macaroon (read-only mount)
	// AdminMacaroonHex, when set, is used instead of AdminMacaroon: the
	// process read the file while it still could (as root, before dropping
	// privileges) and holds it in memory. In this mode a rotation of LND's
	// macaroons cannot be picked up by re-reading, so the guard exits and
	// is restarted by the runtime, which reads the new file.
	AdminMacaroonHex string
	CredentialsDir   string // where recv/spend.macaroon and status.json are written
	StateDir         string // guard-private state (latch, caps, authorizations)
	SocketPath       string
	AllowedUIDs      []uint32 // peers that may call the socket (core)
	IPRange          *net.IPNet
	Log              *slog.Logger
}

// Status is what the guard reports about itself; the same document is written
// to credentials/status.json so health checks need no socket round trip.
type Status struct {
	UpdatedAt       time.Time `json:"updated_at"`
	LNDState        string    `json:"lnd_state"`
	LNDReachable    bool      `json:"lnd_reachable"`
	NodePubkey      string    `json:"node_pubkey,omitempty"`
	AdminMacaroonOK bool      `json:"admin_macaroon_ok"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorAt     time.Time `json:"last_error_at,omitempty"`

	ReceiveBakedAt time.Time `json:"receive_baked_at,omitempty"`
	ReceiveExpires time.Time `json:"receive_expires,omitempty"`
	ReceiveCaveats []string  `json:"receive_caveats,omitempty"`
	ReceiveMethods []string  `json:"receive_methods"`

	SendingEnabled       bool      `json:"sending_enabled"`
	MiddlewareRegistered bool      `json:"middleware_registered"`
	MaxPaymentMsat       int64     `json:"max_payment_msat"`
	Max24hMsat           int64     `json:"max_24h_msat"`
	Spent24hMsat         int64     `json:"spent_24h_msat"`
	ReservedMsat         int64     `json:"reserved_msat"`
	SpendBakedAt         time.Time `json:"spend_baked_at,omitempty"`
	SpendExpires         time.Time `json:"spend_expires,omitempty"`
	SpendCaveats         []string  `json:"spend_caveats,omitempty"`
	SpendMethods         []string  `json:"spend_methods"`

	// Liquidity is filled in on a status request only; it is not part of
	// status.json. See liquidity.go.
	Liquidity *Liquidity `json:"liquidity,omitempty"`
}

// Guard is the running broker.
type Guard struct {
	cfg    Config
	log    *slog.Logger
	mu     sync.Mutex
	status Status
	kick   chan struct{}

	stateMu      sync.Mutex
	state        State
	reservations map[uint64]*reservation

	liqMu sync.Mutex
	liq   *Liquidity
}

// New validates the configuration and returns a Guard ready to Run.
func New(cfg Config) (*Guard, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	for _, d := range []string{cfg.CredentialsDir, cfg.StateDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	g := &Guard{cfg: cfg, log: cfg.Log, kick: make(chan struct{}, 1), reservations: map[uint64]*reservation{}}
	g.status.ReceiveMethods = ReceiveMethods
	g.status.SpendMethods = SpendMethods
	if err := g.loadState(); err != nil {
		return nil, err
	}
	return g, nil
}

// Run bakes, renews, serves the middleware and the socket until ctx ends.
func (g *Guard) Run(ctx context.Context) error {
	srv := &ipc.Server{
		Path:        g.cfg.SocketPath,
		AllowedUIDs: g.cfg.AllowedUIDs,
		Handler:     g.handle,
		Log:         g.log,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(ctx) }()
	if g.cfg.LNDGRPCAddress != "" {
		go g.runMiddleware(ctx)
	} else {
		g.log.Warn("guard: no LND gRPC address; the spend middleware cannot register, sending stays off")
	}

	ticker := time.NewTicker(RenewInterval)
	defer ticker.Stop()
	auth := time.NewTicker(AuthPoll)
	defer auth.Stop()
	g.applyAuthorization()
	g.ensure(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return fmt.Errorf("guard socket: %w", err)
		case <-ticker.C:
			g.ensure(ctx)
		case <-auth.C:
			g.applyAuthorization()
		case <-g.kick:
			g.ensure(ctx)
		}
	}
}

func (g *Guard) handle(ctx context.Context, req ipc.Request) (any, error) {
	switch req.Type {
	case "status":
		st := g.snapshot()
		st.Liquidity = g.liquidity(ctx, st)
		return st, nil
	case "rebake":
		select {
		case g.kick <- struct{}{}:
		default:
		}
		return map[string]bool{"queued": true}, nil
	case "lower_caps":
		var p struct {
			MaxPaymentMsat int64 `json:"max_payment_msat"`
			Max24hMsat     int64 `json:"max_24h_msat"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, errors.New("bad request")
		}
		if err := g.LowerCaps(p.MaxPaymentMsat, p.Max24hMsat); err != nil {
			return nil, err
		}
		g.refreshSpendStatus()
		return g.snapshot(), nil
	case "disable_sending":
		if err := g.DisableSending(); err != nil {
			return nil, err
		}
		return g.snapshot(), nil
	default:
		return nil, fmt.Errorf("unknown request %q", req.Type)
	}
}

func (g *Guard) snapshot() Status {
	g.refreshSpendStatus()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// refreshSpendStatus copies the policy numbers into the status document.
func (g *Guard) refreshSpendStatus() {
	now := time.Now()
	g.stateMu.Lock()
	enabled, maxP, max24, spent, reserved := g.state.SendingEnabled, g.state.MaxPaymentMsat, g.state.Max24hMsat, g.spentLocked(now), g.reservedLocked()
	g.stateMu.Unlock()
	g.update(func(s *Status) {
		s.SendingEnabled, s.MaxPaymentMsat, s.Max24hMsat, s.Spent24hMsat, s.ReservedMsat = enabled, maxP, max24, spent, reserved
	})
}

func (g *Guard) update(fn func(*Status)) {
	g.mu.Lock()
	fn(&g.status)
	g.status.UpdatedAt = time.Now().UTC()
	snap := g.status
	g.mu.Unlock()
	b, _ := json.MarshalIndent(snap, "", "  ")
	_ = writeAtomic(filepath.Join(g.cfg.CredentialsDir, "status.json"), b, 0o644)
}

func (g *Guard) fail(err error) {
	g.log.Warn("guard", "err", err)
	g.update(func(s *Status) {
		s.LastError = err.Error()
		s.LastErrorAt = time.Now().UTC()
	})
}

// ensure makes sure the credentials the policy calls for exist and are far
// from expiry, baking fresh ones otherwise. It retries quickly while LND is
// still locked.
func (g *Guard) ensure(ctx context.Context) {
	adminHex, err := g.adminMacaroon()
	if err != nil {
		g.update(func(s *Status) { s.AdminMacaroonOK = false })
		g.fail(fmt.Errorf("admin macaroon: %w", err))
		g.retrySoon()
		return
	}
	g.update(func(s *Status) { s.AdminMacaroonOK = true })

	cli, err := lnd.New(g.cfg.LNDRestURL, g.cfg.LNDCAFile, "")
	if err != nil {
		g.fail(err)
		g.retrySoon()
		return
	}
	state, err := cli.GetState(ctx)
	if err != nil {
		g.update(func(s *Status) { s.LNDReachable = false; s.LNDState = "" })
		g.fail(fmt.Errorf("lnd state: %w", err))
		g.retrySoon()
		return
	}
	g.update(func(s *Status) { s.LNDReachable = true; s.LNDState = state })
	if state != "RPC_ACTIVE" && state != "SERVER_ACTIVE" {
		g.log.Info("guard: waiting for LND", "state", state)
		g.retrySoon()
		return
	}
	cli.SetMacaroonHex(adminHex)
	if info, err := cli.GetInfo(ctx); err == nil {
		g.update(func(s *Status) { s.NodePubkey = info.IdentityPubkey })
	} else if lnd.IsPermissionDenied(err) {
		// The node stopped accepting admin.macaroon: a rotation. With a file
		// path the next read picks the new file up; with a preloaded
		// macaroon only a restart can, so exit and let the runtime do it.
		g.fail(fmt.Errorf("admin macaroon rejected (rotated?): %w", err))
		if g.cfg.AdminMacaroonHex != "" {
			g.log.Error("guard: admin macaroon rejected and held in memory; exiting so the runtime restarts the guard to reload it")
			g.exit(3)
		}
		g.retrySoon()
		return
	}

	st := g.snapshot()
	if st.ReceiveExpires.IsZero() || time.Until(st.ReceiveExpires) <= RenewBefore || !fileExists(g.receivePath()) {
		if err := g.bakeReceive(ctx, cli); err != nil {
			g.fail(fmt.Errorf("bake receive credential: %w", err))
			g.retrySoon()
			return
		}
	}
	g.ensureSpend(ctx, cli, st)
}

// ensureSpend bakes or drops the spend credential according to the latch.
// It exists only while sending is on AND the middleware is registered: a
// credential whose caveat nobody serves is dead on arrival, but baking it
// anyway would make "sending on, middleware down" look like a bake failure.
func (g *Guard) ensureSpend(ctx context.Context, cli *lnd.Client, st Status) {
	g.stateMu.Lock()
	enabled, nonce := g.state.SendingEnabled, g.state.Nonce
	g.stateMu.Unlock()
	if !enabled {
		if fileExists(g.spendPath()) {
			g.dropSpendCredential()
		}
		return
	}
	if !st.MiddlewareRegistered {
		g.log.Info("guard: sending is enabled but the middleware is not registered yet; spend credential waits")
		return
	}
	fresh := !st.SpendExpires.IsZero() && time.Until(st.SpendExpires) > RenewBefore && fileExists(g.spendPath())
	sameNonce := false
	for _, c := range st.SpendCaveats {
		if c == macaroon.CustomCaveat(MiddlewareName, nonce) {
			sameNonce = true
		}
	}
	if fresh && sameNonce {
		return
	}
	if err := g.bakeSpend(ctx, cli, nonce); err != nil {
		g.fail(fmt.Errorf("bake spend credential: %w", err))
		g.retrySoon()
	}
}

func (g *Guard) retrySoon() {
	go func() {
		time.Sleep(15 * time.Second)
		select {
		case g.kick <- struct{}{}:
		default:
		}
	}()
}

func (g *Guard) receivePath() string { return filepath.Join(g.cfg.CredentialsDir, "recv.macaroon") }
func (g *Guard) spendPath() string   { return filepath.Join(g.cfg.CredentialsDir, "spend.macaroon") }

func (g *Guard) baseCaveats(expires time.Time) []string {
	caveats := []string{macaroon.TimeBeforeCaveat(expires)}
	if g.cfg.IPRange != nil {
		caveats = append(caveats, macaroon.IPRangeCaveat(g.cfg.IPRange))
	}
	return caveats
}

func (g *Guard) bakeReceive(ctx context.Context, cli *lnd.Client) error {
	baked, err := cli.BakeMacaroon(ctx, lnd.URIPermissions(ReceiveMethods...))
	if err != nil {
		return err
	}
	expires := time.Now().Add(Validity)
	caveats := g.baseCaveats(expires)
	hardened, err := macaroon.AddCaveats(baked, caveats...)
	if err != nil {
		return err
	}
	// Prove the credential works before publishing it: a wrong iprange fails
	// closed and would otherwise read like a bake failure on the core side.
	probe, err := lnd.New(g.cfg.LNDRestURL, g.cfg.LNDCAFile, "")
	if err != nil {
		return err
	}
	probe.SetMacaroonHex(hardened)
	if _, err := probe.GetInfo(ctx); err != nil {
		return fmt.Errorf("baked credential rejected by LND (caveats %v): %w", caveats, err)
	}
	raw, _ := hex.DecodeString(hardened)
	if err := writeAtomic(g.receivePath(), raw, 0o644); err != nil {
		return err
	}
	g.log.Info("guard: receive credential baked", "expires", expires.UTC().Format(time.RFC3339), "caveats", caveats)
	g.update(func(s *Status) {
		s.ReceiveBakedAt = time.Now().UTC()
		s.ReceiveExpires = expires.UTC()
		s.ReceiveCaveats = caveats
		s.LastError = ""
	})
	return nil
}

func (g *Guard) bakeSpend(ctx context.Context, cli *lnd.Client, nonce string) error {
	if nonce == "" {
		return errors.New("no sending nonce; authorize sending first")
	}
	baked, err := cli.BakeMacaroon(ctx, lnd.URIPermissions(SpendMethods...))
	if err != nil {
		return err
	}
	expires := time.Now().Add(Validity)
	caveats := append(g.baseCaveats(expires), macaroon.CustomCaveat(MiddlewareName, nonce))
	hardened, err := macaroon.AddCaveats(baked, caveats...)
	if err != nil {
		return err
	}
	raw, _ := hex.DecodeString(hardened)
	if err := writeAtomic(g.spendPath(), raw, 0o644); err != nil {
		return err
	}
	g.log.Info("guard: spend credential baked", "expires", expires.UTC().Format(time.RFC3339), "caveats", caveats)
	g.update(func(s *Status) {
		s.SpendBakedAt = time.Now().UTC()
		s.SpendExpires = expires.UTC()
		s.SpendCaveats = caveats
		s.SendingEnabled = true
	})
	return nil
}

// adminMacaroon returns the admin macaroon as hex, from memory or disk.
func (g *Guard) adminMacaroon() (string, error) {
	if g.cfg.AdminMacaroonHex != "" {
		return g.cfg.AdminMacaroonHex, nil
	}
	return readMacaroonHex(g.cfg.AdminMacaroon)
}

// ReadMacaroonHex reads a macaroon file as hex. Exported for the command,
// which reads admin.macaroon before dropping privileges.
func ReadMacaroonHex(path string) (string, error) { return readMacaroonHex(path) }

// exit is os.Exit, replaceable in tests.
var exitFunc = os.Exit

func (g *Guard) exit(code int) { exitFunc(code) }

func readMacaroonHex(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) < 32 {
		return "", errors.New("file too small to be a macaroon")
	}
	return hex.EncodeToString(raw), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Size() > 0
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Package edge is the public HTTP process: LNURL-pay, Lightning Address,
// NIP-05, the embedded relay and an optional static site. It holds no
// credentials; the only privileged thing it can do is ask core for an invoice
// over a unix socket with a fixed, bounded schema.
package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiatjaf/khatru"

	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/identity"
	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnurl"
	"github.com/lundog/lightning-identity-startos/service/internal/site"
	"github.com/lundog/lightning-identity-startos/service/internal/zap"
)

// Options configures the edge server.
type Options struct {
	Identities *identity.Watcher
	Core       *ipc.Client
	Relay      *khatru.Relay
	SiteDir    string // optional static site served at /
	Log        *slog.Logger
	// Rate limits: per-identity invoice requests and per-client requests
	// (the bucket holds one minute's worth, so that is also the burst).
	InvoicesPerMinute int
	RequestsPerMinute int
}

// DefaultRequestsPerMinute is the per-client limit. A browser needs about
// seven requests for a landing page and a wallet two or three to pay a
// Lightning Address. The first value, 120 a minute with a burst of 240, let
// a scanner make 150 requests in 27 seconds without ever being refused.
const DefaultRequestsPerMinute = 60

// healthTTL is how long a core health answer is reused. /health is public,
// and each uncached answer is a call into core and on to LND.
const healthTTL = 10 * time.Second

// Server is the edge HTTP handler.
type Server struct {
	o       Options
	mux     *http.ServeMux
	perName *httpx.Limiter
	perIP   *httpx.Limiter
	noted   *httpx.Limiter // at most one "rate limited" log line a minute per client
	abuse   *missGuard
	site    http.Handler // serves Options.SiteDir; used only while it holds a site

	healthMu sync.Mutex
	healthAt time.Time
	healthOK bool
}

// New wires the routes.
func New(o Options) *Server {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.InvoicesPerMinute <= 0 {
		o.InvoicesPerMinute = 60
	}
	if o.RequestsPerMinute <= 0 {
		o.RequestsPerMinute = DefaultRequestsPerMinute
	}
	s := &Server{
		o:       o,
		mux:     http.NewServeMux(),
		perName: httpx.NewLimiter(o.InvoicesPerMinute, o.InvoicesPerMinute),
		perIP:   httpx.NewLimiter(o.RequestsPerMinute, o.RequestsPerMinute),
		noted:   httpx.NewLimiter(1, 1),
		abuse:   newMissGuard(),
	}
	s.mux.HandleFunc("GET /.well-known/lnurlp/{name}", s.lnurlp)
	s.mux.HandleFunc("GET /lnurlp/{name}/callback", s.callback)
	s.mux.HandleFunc("GET /lnurlp/{name}/verify/{hash}", s.verify)
	s.mux.HandleFunc("GET /.well-known/nostr.json", s.nip05)
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("/relay", s.relay)
	s.mux.HandleFunc("/relay/", s.relay)
	// A site is served while the folder holds an index.html, which root
	// checks on each request: the Upload Site and Remove Site actions (or an
	// operator with a file manager) change the folder while this runs, and a
	// restart to notice would drop every wallet's relay connection.
	if o.SiteDir != "" {
		s.site = http.FileServer(noDirListing{http.Dir(o.SiteDir)})
	}
	s.mux.HandleFunc("/", s.root)
	return s
}

// ServeHTTP applies the per-client limits and security headers, then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	key := httpx.RateKey(ip)
	local := fromThisHost(r) // core, over loopback: not a client to be limited
	if !local {
		// A blocked scanner is refused before anything else and without a
		// log line: the block itself was logged, once.
		blocked, left, lifted := s.abuse.refuse(key)
		if lifted != nil {
			s.o.Log.Info("edge: block expired", "ip", ip, "refused", lifted.refused)
		}
		if blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		if !s.perIP.Allow(key) {
			if s.noted.Allow(key) {
				s.o.Log.Warn("edge: rate limited", "ip", ip, "path", r.URL.Path, "note", "logged at most once a minute per address")
			}
			w.Header().Set("Retry-After", "5")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// One access-log line per request with the client address (rightmost
	// X-Forwarded-For, which the OS proxy sets; see README). WebSocket
	// upgrades on /relay are logged at upgrade time, with the hijacked
	// status left as 101.
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	s.mux.ServeHTTP(sw, r)
	if sw.hijacked {
		sw.status = http.StatusSwitchingProtocols
	}
	s.o.Log.Info("edge: request", "ip", ip, "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds(), "ua", r.UserAgent())
	if !local && isMiss(sw.status) && blockable(ip) && s.abuse.miss(key) {
		s.o.Log.Warn("edge: address blocked", "ip", ip, "why", "more than "+strconv.Itoa(MissesPerMinute)+" not-found requests in a minute", "minutes", int(BlockFor.Minutes()), "last_path", r.URL.Path)
	}
}

// statusWriter records the status code (and whether the connection was
// hijacked for a WebSocket) for the access log.
type statusWriter struct {
	http.ResponseWriter
	status   int
	hijacked bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	w.hijacked = true
	return hj.Hijack()
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
}

func (s *Server) lnurlp(w http.ResponseWriter, r *http.Request) {
	cors(w)
	doc := s.o.Identities.Doc()
	e := doc.Find(r.PathValue("name"))
	if e == nil || doc.BaseURL == "" {
		httpx.LNURLError(w, http.StatusNotFound, "unknown address")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	httpx.JSON(w, http.StatusOK, lnurl.BuildPayResponse(doc, e))
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	cors(w)
	doc := s.o.Identities.Doc()
	name := strings.ToLower(r.PathValue("name"))
	e := doc.Find(name)
	if e == nil {
		httpx.LNURLError(w, http.StatusNotFound, "unknown address")
		return
	}
	if !s.perName.Allow(name) {
		httpx.LNURLError(w, http.StatusTooManyRequests, "too many invoice requests for this address, try again shortly")
		return
	}
	q := r.URL.Query()
	amount, err := strconv.ParseInt(q.Get("amount"), 10, 64)
	if err != nil {
		httpx.LNURLError(w, http.StatusBadRequest, "amount (msat) is required")
		return
	}
	if err := lnurl.ValidateAmount(e.MinMsat, e.MaxMsat, amount); err != nil {
		httpx.LNURLError(w, http.StatusBadRequest, err.Error())
		return
	}
	req := lnurl.CallbackRequest{Identity: name, AmountMsat: amount}
	if c := q.Get("comment"); c != "" {
		if err := lnurl.ValidateComment(e.CommentAllowed, c); err != nil {
			httpx.LNURLError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Comment = c
	}
	if pd := q.Get("payerdata"); pd != "" {
		clean, err := lnurl.ValidatePayerData(pd)
		if err != nil {
			httpx.LNURLError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.PayerData = clean
	}
	if zr := q.Get("nostr"); zr != "" {
		if e.ZapPubkey == "" {
			httpx.LNURLError(w, http.StatusBadRequest, "zaps are not enabled for this address")
			return
		}
		if len(zr) > lnurl.MaxZapRequest {
			httpx.LNURLError(w, http.StatusBadRequest, "zap request too large")
			return
		}
		zreq, err := zap.Validate(zr, amount)
		if err != nil {
			s.o.Log.Warn("zap request rejected", "name", name, "amount_msat", amount, "ip", httpx.ClientIP(r), "err", err)
			httpx.LNURLError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.o.Log.Info("nostr: zap request", "kind", zreq.Event.Kind, "id", zreq.Event.ID, "pubkey", zreq.Event.PubKey, "p", zreq.Recipient, "e", zreq.EventID, "name", name, "amount_msat", amount, "relays", zreq.Relays, "ip", httpx.ClientIP(r))
		req.ZapRequest = zr
	}
	var res struct {
		PR          string `json:"pr"`
		PaymentHash string `json:"payment_hash"`
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.o.Core.Call(ctx, "create_invoice", req, &res); err != nil {
		var re *ipc.RemoteError
		if errors.As(err, &re) {
			httpx.LNURLError(w, http.StatusBadGateway, re.Msg)
		} else {
			s.o.Log.Warn("edge: core unavailable", "err", err)
			httpx.LNURLError(w, http.StatusServiceUnavailable, "the node is not available right now")
		}
		return
	}
	httpx.JSON(w, http.StatusOK, lnurl.CallbackResponse{
		PR:     res.PR,
		Routes: []string{},
		Verify: strings.TrimRight(doc.BaseURL, "/") + "/lnurlp/" + name + "/verify/" + res.PaymentHash,
	})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	cors(w)
	hash := strings.ToLower(r.PathValue("hash"))
	if len(hash) != 64 {
		httpx.LNURLError(w, http.StatusBadRequest, "bad payment hash")
		return
	}
	var res lnurl.VerifyResponse
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.o.Core.Call(ctx, "verify_invoice", map[string]string{"payment_hash": hash, "identity": strings.ToLower(r.PathValue("name"))}, &res); err != nil {
		httpx.LNURLError(w, http.StatusNotFound, "unknown invoice")
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

func (s *Server) nip05(w http.ResponseWriter, r *http.Request) {
	cors(w)
	doc := s.o.Identities.Doc()
	names := map[string]string{}
	want := strings.ToLower(r.URL.Query().Get("name"))
	for _, e := range doc.Identities {
		if !e.NIP05 || e.UserPubkey == "" {
			continue
		}
		if want != "" && e.Name != want {
			continue
		}
		names[e.Name] = e.UserPubkey
	}
	// No "relays" hint on purpose: NIP-05's hint says where the user's own
	// events live, and this service's relay is not that — it holds zap
	// receipts and NWC traffic only. Wallet apps learn the NWC relay from
	// the connection string.
	out := map[string]any{"names": names}
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpx.JSON(w, http.StatusOK, out)
}

// health answers whether the service can do its job: 200 {"ok":true} when
// core (and through it LND) answers, 503 {"ok":false} when it does not. It
// says nothing else. This endpoint is on the public interface, so it tells
// a stranger neither how many identities there are nor how long the service
// has been up, and however often it is asked, core is asked at most once
// per healthTTL.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if s.coreHealthy() {
		httpx.JSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	httpx.JSON(w, http.StatusServiceUnavailable, map[string]bool{"ok": false})
}

// coreHealthy returns core's status, asking it only when the last answer is
// older than healthTTL. The lock is held across the call on purpose: a
// burst of requests waits for one answer instead of each making its own.
func (s *Server) coreHealthy() bool {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if !s.healthAt.IsZero() && time.Since(s.healthAt) < healthTTL {
		return s.healthOK
	}
	var st struct {
		OK bool `json:"ok"`
	}
	// Not the request's context: a caller that hangs up must not leave a
	// false "unhealthy" behind for the next ten seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.healthOK = s.o.Core.Call(ctx, "status", nil, &st) == nil && st.OK
	s.healthAt = time.Now()
	return s.healthOK
}

func (s *Server) relay(w http.ResponseWriter, r *http.Request) {
	if s.o.Relay == nil {
		http.NotFound(w, r)
		return
	}
	// khatru answers the WebSocket upgrade and the NIP-11 document itself;
	// a plain browser GET gets a one-line explanation instead of a 404.
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
		s.o.Relay.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("This is a Nostr relay. Connect with a Nostr client over WebSocket.\n"))
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	// Everything served from here is a document to read. (A file server
	// answers a POST with the file just the same, which is how a scanner's
	// POST / came back 200.)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.site != nil && site.Present(s.o.SiteDir) {
		// Hidden files are never part of a site: not a .env or .git that
		// came along with the folder, not the installer's work folders.
		if !site.Served(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		s.site.ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Lightning addresses are served from this domain.\n"))
}

// noDirListing hides directory indexes from the static site.
type noDirListing struct{ fs http.FileSystem }

func (n noDirListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.IsDir() {
		idx, err := n.fs.Open(filepath.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return f, nil
}

// marshal is used by tests.
func marshal(v any) string { b, _ := json.Marshal(v); return string(b) }

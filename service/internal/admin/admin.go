// Package admin is the operator UI core serves on the LAN-only interface:
// identities, NWC connections, recent invoices and the node/guard status.
// It is server-rendered HTML behind a password session; nothing here is
// reachable from the public interface.
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
	"github.com/lundog/lightning-identity-startos/service/internal/pw"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

// iconSVG is the package icon, shown in the header and as the favicon. It is
// a copy of icon.svg at the repository root (go:embed cannot reach outside
// the module); a test fails if the two differ.
//
//go:embed static/icon.svg
var iconSVG []byte

// groupDigits writes n with thousands separators: 1234567 -> "1,234,567".
func groupDigits(n int64) string {
	s := strconv.FormatInt(n, 10)
	if n < 0 {
		return "-" + groupDigits(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// sats writes an amount the way wallets do: "1 sat", "0 sats", "21,000 sats".
func sats(n int64) string {
	if n == 1 {
		return "1 sat"
	}
	return groupDigits(n) + " sats"
}

// signedSats is sats for an amount that may be negative (a balance after a
// debit).
func signedSats(n int64) string {
	if n < 0 {
		return "−" + sats(-n)
	}
	return sats(n)
}

// liquidityView is the guard's channel summary as the dashboard shows it.
type liquidityView struct {
	Known bool   // the guard reported one
	Error string // it could not read the channels

	Channels int `json:"channels"`
	Active   int `json:"active"`
	Offline  int

	CanSendMsat        int64 `json:"can_send_msat"`
	CanReceiveMsat     int64 `json:"can_receive_msat"`
	LargestSendMsat    int64 `json:"largest_send_msat"`
	LargestReceiveMsat int64 `json:"largest_receive_msat"`
	OfflineSendMsat    int64 `json:"offline_send_msat"`
	UnsettledMsat      int64 `json:"unsettled_msat"`

	List []struct {
		Peer           string `json:"peer"`   // alias; "" when the node has none on record
		Pubkey         string `json:"pubkey"` // node key, hex
		Active         bool   `json:"active"`
		Unannounced    bool   `json:"unannounced"`
		CanSendMsat    int64  `json:"can_send_msat"`
		CanReceiveMsat int64  `json:"can_receive_msat"`
	} `json:"list"`

	// ShortMsat is how much of the identities' balances the node could not
	// pay out right now: balances minus what it can send, when positive.
	ShortMsat int64
}

// newLiquidityView reads the "liquidity" part of the guard's status and
// compares it with what the identities hold.
func newLiquidityView(guard map[string]any, balancesMsat int64) liquidityView {
	var v liquidityView
	raw, ok := guard["liquidity"]
	if !ok || raw == nil {
		return v
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return v
	}
	var wire struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &wire)
	if err := json.Unmarshal(b, &v); err != nil {
		return liquidityView{}
	}
	v.Known, v.Error = true, wire.Error
	v.Offline = v.Channels - v.Active
	if balancesMsat > v.CanSendMsat {
		v.ShortMsat = balancesMsat - v.CanSendMsat
	}
	return v
}

const (
	sessionCookie = "li_session"
	sessionTTL    = 12 * time.Hour
)

// Options configures the admin server.
type Options struct {
	Core         *core.Service
	NWC          *nwc.Service
	PasswordHash string // scrypt hash from the package store; "" disables login
	Log          *slog.Logger
}

// Server is the admin HTTP handler.
type Server struct {
	o     Options
	mux   *http.ServeMux
	tmpl  *template.Template
	login *httpx.Limiter

	mu       sync.Mutex
	sessions map[string]time.Time
	flashes  map[string]flash // one-shot results keyed by session token
}

type flash struct {
	Title, Message, Secret string
	QR                     template.URL // a data: URI html/template would otherwise refuse
	Error                  bool
}

// New builds the handler.
func New(o Options) (*Server, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	funcs := template.FuncMap{
		"msat": func(v int64) string {
			if v < 0 {
				return "−" + sats(-v/1000)
			}
			return sats(v / 1000)
		},
		"smsat": func(v int64) string { // signed, for adjustments and positions
			if v < 0 {
				return "−" + sats(-v/1000)
			}
			return "+" + sats(v/1000)
		},
		"div1000": func(v int64) int64 { return v / 1000 },
		"div60":   func(v int64) int64 { return v / 60 },
		"pct":     func(ppm int64) string { return strconv.FormatFloat(float64(ppm)/10_000, 'f', -1, 64) },
		"int64": func(v any) int64 {
			switch n := v.(type) {
			case float64:
				return int64(n)
			case int64:
				return n
			case int:
				return int64(n)
			case json.Number:
				i, _ := n.Int64()
				return i
			}
			return 0
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			default:
				return t.Format("2006-01-02")
			}
		},
		"short": func(s string) string {
			if len(s) > 16 {
				return s[:8] + "…" + s[len(s)-8:]
			}
			return s
		},
		"join": strings.Join,
		// dict builds the argument of a sub-template from key, value pairs.
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, errors.New("dict needs key, value pairs")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				k, ok := kv[i].(string)
				if !ok {
					return nil, errors.New("dict keys are strings")
				}
				m[k] = kv[i+1]
			}
			return m, nil
		},
		"npub": func(hexPK string) string {
			if n, err := encodeNpub(hexPK); err == nil {
				return n
			}
			return hexPK
		},
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{o: o, mux: http.NewServeMux(), tmpl: tmpl, login: httpx.NewLimiter(10, 10), sessions: map[string]time.Time{}, flashes: map[string]flash{}}
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginPost)
	s.mux.HandleFunc("POST /logout", s.auth(s.logout))
	s.mux.HandleFunc("GET /", s.auth(s.dashboard))
	s.mux.HandleFunc("GET /system", s.auth(s.system))
	s.mux.HandleFunc("GET /identities/new", s.auth(s.identityNew))
	s.mux.HandleFunc("POST /identities", s.auth(s.identityCreate))
	s.mux.HandleFunc("GET /identities/{id}", s.auth(s.identityPage))
	s.mux.HandleFunc("POST /identities/{id}/update", s.auth(s.identityUpdate))
	s.mux.HandleFunc("POST /identities/{id}/delete", s.auth(s.identityDelete))
	s.mux.HandleFunc("POST /identities/{id}/rotate-zap", s.auth(s.identityRotateZap))
	s.mux.HandleFunc("POST /identities/{id}/rotate-nwc", s.auth(s.identityRotateNWC))
	s.mux.HandleFunc("POST /identities/{id}/adjust", s.auth(s.identityAdjust))
	s.mux.HandleFunc("POST /identities/{id}/connections", s.auth(s.connectionCreate))
	s.mux.HandleFunc("POST /connections/{id}/revoke", s.auth(s.connectionRevoke))
	s.mux.HandleFunc("POST /settings", s.auth(s.settingsUpdate))
	s.mux.HandleFunc("POST /sending/lower-caps", s.auth(s.sendingLowerCaps))
	s.mux.HandleFunc("POST /sending/disable", s.auth(s.sendingDisable))
	s.mux.HandleFunc("GET /health", s.health)
	// The icon is public (the login page shows it) and the same for
	// everyone, so unlike every page it may be cached.
	s.mux.HandleFunc("GET /icon.svg", s.icon)
	s.mux.HandleFunc("GET /favicon.ico", s.icon)
	return s, nil
}

// ServeHTTP adds headers and routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	s.mux.ServeHTTP(w, r)
}

// ---- sessions ----

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.o.PasswordHash == "" {
			s.render(w, "login.html", map[string]any{"NoPassword": true, "HideLogout": true})
			return
		}
		if !s.validSession(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

func (s *Server) sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]any{"NoPassword": s.o.PasswordHash == "", "HideLogout": true})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if !s.login.Allow(ip) || !s.login.Allow("*") {
		time.Sleep(2 * time.Second)
		s.render(w, "login.html", map[string]any{"Error": "Too many attempts. Wait a minute and try again.", "HideLogout": true})
		return
	}
	if s.o.PasswordHash == "" || !pw.Verify(s.o.PasswordHash, r.FormValue("password")) {
		time.Sleep(500 * time.Millisecond)
		s.render(w, "login.html", map[string]any{"Error": "Wrong password.", "HideLogout": true})
		return
	}
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	token := hex.EncodeToString(tok)
	s.mu.Lock()
	for k, exp := range s.sessions {
		if time.Now().After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	tok := s.sessionToken(r)
	s.mu.Lock()
	delete(s.sessions, tok)
	delete(s.flashes, tok)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setFlash(r *http.Request, f flash) {
	s.mu.Lock()
	s.flashes[s.sessionToken(r)] = f
	s.mu.Unlock()
}

func (s *Server) takeFlash(r *http.Request) *flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := s.sessionToken(r)
	f, ok := s.flashes[tok]
	if !ok {
		return nil
	}
	delete(s.flashes, tok)
	return &f
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Domain"] = s.o.Core.Domain()
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.o.Log.Error("render", "template", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// ---- pages ----

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ids, _ := s.o.Core.Store().ListIdentities()
	balances := map[string]store.Balance{}
	var total int64
	for _, id := range ids {
		b, _ := s.o.Core.Balance(id.ID)
		balances[id.ID] = b
		total += b.Available
	}
	guard, gerr := s.o.Core.GuardStatus(ctx)
	info, ierr := s.o.Core.NodeInfo(ctx)
	data := map[string]any{
		"OnDashboard": true,
		"Identities":  ids,
		"Balances":    balances,
		"TotalMsat":   total,
		"Guard":       guard,
		"GuardErr":    errString(gerr),
		"Problems":    problems(guard, gerr, info, ierr),
		"Config":      s.o.Core.Config(),
		"Flash":       s.takeFlash(r),
		"Sending":     s.o.Core.SendingEnabled(),
		"Settings":    s.o.Core.Settings(),
		"Liquidity":   newLiquidityView(guard, total),
	}
	s.render(w, "dashboard.html", data)
}

// system is where the plumbing is shown: the node, the guard and the
// credentials it bakes. The dashboard carries only what an operator acts on,
// and names anything here that is wrong (see problems).
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	guard, gerr := s.o.Core.GuardStatus(ctx)
	info, ierr := s.o.Core.NodeInfo(ctx)
	s.render(w, "system.html", map[string]any{
		"OnSystem": true,
		"Sys":      newSystemView(guard),
		"GuardErr": errString(gerr),
		"Node":     info,
		"NodeErr":  errString(ierr),
		"Config":   s.o.Core.Config(),
		"Flash":    s.takeFlash(r),
	})
}

// credentialView is one baked credential as the System page shows it.
type credentialView struct {
	Baked   bool
	Expires string // "2026-11-19 14:03 UTC", empty when not baked
	Methods []string
	Caveats []string
}

// systemView is the guard's status, typed. The status arrives as JSON over
// the guard socket, where a time that was never set is year 1, not absent.
type systemView struct {
	LNDState       string
	AdminOK        bool
	LastError      string
	Receive        credentialView
	SendingEnabled bool
	Middleware     bool
	Spend          credentialView
}

func guardTime(guard map[string]any, key string) (time.Time, bool) {
	raw, _ := guard[key].(string)
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, true
}

func guardStrings(guard map[string]any, key string) []string {
	list, _ := guard[key].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func newCredentialView(guard map[string]any, prefix string) credentialView {
	v := credentialView{Methods: guardStrings(guard, prefix+"_methods"), Caveats: guardStrings(guard, prefix+"_caveats")}
	if t, ok := guardTime(guard, prefix+"_expires"); ok {
		v.Baked = true
		v.Expires = t.UTC().Format("2006-01-02 15:04 UTC")
	}
	return v
}

func newSystemView(guard map[string]any) systemView {
	v := systemView{Receive: newCredentialView(guard, "receive"), Spend: newCredentialView(guard, "spend")}
	v.LNDState, _ = guard["lnd_state"].(string)
	v.AdminOK, _ = guard["admin_macaroon_ok"].(bool)
	v.LastError, _ = guard["last_error"].(string)
	v.SendingEnabled, _ = guard["sending_enabled"].(bool)
	v.Middleware, _ = guard["middleware_registered"].(bool)
	return v
}

// problems lists, in plain sentences, whatever on the System page stops the
// service from doing its job. Moving the detail off the dashboard must not
// hide a fault, so each one is named there until it clears.
func problems(guard map[string]any, guardErr error, node *lnd.Info, nodeErr error) []string {
	var out []string
	if guardErr != nil {
		out = append(out, "The guard is not answering ("+guardErr.Error()+"). Credentials cannot be renewed and nothing can be sent.")
	} else {
		if e, _ := guard["last_error"].(string); e != "" {
			out = append(out, "The guard reports: "+e)
		}
		if _, baked := guardTime(guard, "receive_expires"); !baked {
			out = append(out, "There is no receive credential yet, so invoices cannot be created. The guard bakes one as soon as LND is unlocked and reachable.")
		}
		if on, _ := guard["sending_enabled"].(bool); on {
			if reg, _ := guard["middleware_registered"].(bool); !reg {
				out = append(out, "Sending is enabled but the guard's caps check is not registered with LND, so LND refuses every payment until it is.")
			}
			if _, baked := guardTime(guard, "spend_expires"); !baked {
				out = append(out, "Sending is enabled but there is no spend credential yet, so payments fail until the guard bakes one.")
			}
		}
	}
	if nodeErr != nil {
		out = append(out, "LND is not reachable ("+nodeErr.Error()+").")
	} else if node != nil && !node.SyncedToChain {
		out = append(out, "LND is not synced to the chain yet.")
	}
	return out
}

func (s *Server) icon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(iconSVG)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) identityNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, "identity_form.html", map[string]any{"New": true, "Config": s.o.Core.Config(), "Identity": &store.Identity{MinSendableMsat: 1000, MaxSendableMsat: 1_000_000_000, CommentAllowed: 255, NIP05Enabled: true}})
}

func parseIdentityForm(r *http.Request, id *store.Identity) error {
	id.Name = strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	id.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
	pk := strings.ToLower(strings.TrimSpace(r.FormValue("user_pubkey")))
	if strings.HasPrefix(pk, "npub1") {
		h, err := decodeNpub(pk)
		if err != nil {
			return errors.New("that npub does not decode")
		}
		pk = h
	}
	if pk != "" && !nostr.IsValidPublicKey(pk) {
		return errors.New("Nostr pubkey must be an npub or 64 hex characters")
	}
	id.UserPubkey = pk
	id.NIP05Enabled = r.FormValue("nip05") == "on" && pk != ""
	min, _ := strconv.ParseInt(r.FormValue("min_sat"), 10, 64)
	max, _ := strconv.ParseInt(r.FormValue("max_sat"), 10, 64)
	id.MinSendableMsat, id.MaxSendableMsat = min*1000, max*1000
	id.CommentAllowed, _ = strconv.Atoi(r.FormValue("comment_allowed"))
	id.Relays = nil
	for _, line := range strings.Split(r.FormValue("relays"), "\n") {
		if l := strings.TrimSpace(line); l != "" {
			id.Relays = append(id.Relays, l)
		}
	}
	id.NWCRelay = strings.TrimSpace(r.FormValue("nwc_relay"))
	id.Disabled = r.FormValue("disabled") == "on"
	return nil
}

func (s *Server) identityCreate(w http.ResponseWriter, r *http.Request) {
	var tmp store.Identity
	if err := parseIdentityForm(r, &tmp); err != nil {
		s.render(w, "identity_form.html", map[string]any{"New": true, "Config": s.o.Core.Config(), "Identity": &tmp, "Error": err.Error()})
		return
	}
	id, err := s.o.Core.NewIdentity(tmp.Name, tmp.DisplayName, tmp.UserPubkey, tmp.NIP05Enabled, tmp.MinSendableMsat, tmp.MaxSendableMsat, tmp.CommentAllowed, tmp.Relays, tmp.NWCRelay)
	if err != nil {
		s.render(w, "identity_form.html", map[string]any{"New": true, "Config": s.o.Core.Config(), "Identity": &tmp, "Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) identityPage(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	conns, _ := s.o.Core.Store().ListConnections(id.ID)
	invs, _ := s.o.Core.Store().ListInvoices(id.ID, 0, 25)
	pays, _ := s.o.Core.Store().ListPayments(id.ID, 0, 25)
	adjs, _ := s.o.Core.Store().ListAdjustments(id.ID, 0, 25)
	bal, _ := s.o.Core.Balance(id.ID)
	s.render(w, "identity.html", map[string]any{
		"Identity":    id,
		"Connections": conns,
		"Invoices":    invs,
		"Payments":    pays,
		"Adjustments": adjs,
		"Balance":     bal,
		"Address":     id.Name + "@" + s.o.Core.Domain(),
		"Flash":       s.takeFlash(r),
		"Methods":     nwc.ReadMethods,
		"Sending":     s.o.Core.SendingEnabled(),
		"Config":      s.o.Core.Config(),
	})
}

func (s *Server) identityUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := parseIdentityForm(r, id); err == nil {
		err = s.o.Core.UpdateIdentity(id)
	}
	if err != nil {
		s.setFlash(r, flash{Title: "Not saved", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Saved", Message: "Identity updated."})
	}
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) identityDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.o.Core.DeleteIdentity(r.PathValue("id")); err != nil {
		s.setFlash(r, flash{Title: "Not deleted", Message: err.Error(), Error: true})
		http.Redirect(w, r, "/identities/"+r.PathValue("id"), http.StatusSeeOther)
		return
	}
	s.setFlash(r, flash{Title: "Deleted", Message: "The identity and its address are gone; its NWC connections are revoked."})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) identityAdjust(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sat, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("amount_sat")), 10, 64)
	if err != nil || sat <= 0 {
		s.setFlash(r, flash{Title: "Not adjusted", Message: "Enter a whole number of sats greater than zero.", Error: true})
		http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
		return
	}
	msat := sat * 1000
	verb := "credited"
	if r.FormValue("direction") == "debit" {
		msat, verb = -msat, "debited"
	}
	if _, err := s.o.Core.Adjust(id, msat, r.FormValue("note")); err != nil {
		s.setFlash(r, flash{Title: "Not adjusted", Message: err.Error(), Error: true})
	} else {
		bal, _ := s.o.Core.Balance(id.ID)
		s.setFlash(r, flash{Title: "Balance " + verb, Message: fmt.Sprintf("%s %s. The identity's balance is now %s. Nothing moved on the node.", sats(sat), verb, signedSats(bal.Available/1000))})
	}
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) identityRotateZap(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.o.Core.RotateZapKey(id); err != nil {
		s.setFlash(r, flash{Title: "Not rotated", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Zap key rotated", Message: "New receipts are signed by the new key; the LNURL document now advertises it."})
	}
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) identityRotateNWC(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.o.Core.RotateNWCKey(id); err != nil {
		s.setFlash(r, flash{Title: "Not rotated", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Wallet service key rotated", Message: "Every connection of this identity was revoked; create new ones."})
	}
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) connectionCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.o.Core.Store().GetIdentity(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	relayURL := s.o.Core.NWCRelayFor(id)
	if relayURL == "" {
		s.setFlash(r, flash{Title: "No relay URL", Message: "Set the primary domain first (or give this identity its own NWC relay); the connection string needs the relay address.", Error: true})
		http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = "connection " + time.Now().Format("2006-01-02 15:04")
	}
	var methods []string
	for _, m := range nwc.AllMethods() {
		if r.FormValue("m_"+m) == "on" {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		methods = []string{"get_info", "make_invoice", "lookup_invoice", "list_transactions"}
	}
	budgetSat, _ := strconv.ParseInt(r.FormValue("budget_sat"), 10, 64)
	maxPaySat, _ := strconv.ParseInt(r.FormValue("max_pay_sat"), 10, 64)
	period := r.FormValue("budget_period")
	switch period {
	case store.PeriodDaily, store.PeriodWeekly, store.PeriodMonthly, store.PeriodYearly, store.PeriodNever:
	default:
		period = store.PeriodMonthly
	}
	clientSK := nostr.GeneratePrivateKey()
	clientPK, _ := nostr.GetPublicKey(clientSK)
	conn := &store.Connection{
		ID:           newID(),
		IdentityID:   id.ID,
		Label:        label,
		ClientPubkey: clientPK,
		Methods:      methods,
		Notify:       r.FormValue("notify") == "on",
		BudgetMsat:   budgetSat * 1000,
		BudgetPeriod: period,
		MaxPayMsat:   maxPaySat * 1000,
		CreatedAt:    time.Now().UTC(),
	}
	if days, _ := strconv.Atoi(r.FormValue("expires_days")); days > 0 {
		t := time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC()
		conn.ExpiresAt = &t
	}
	if err := s.o.Core.Store().PutConnection(conn); err != nil {
		s.setFlash(r, flash{Title: "Not created", Message: err.Error(), Error: true})
		http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
		return
	}
	s.o.Core.PublishIdentities()
	uri := nwc.ConnectionURI(id.NWCPubkey, clientSK, relayURL, id.Name+"@"+s.o.Core.Domain())
	png, _ := qrcode.Encode(uri, qrcode.Medium, 256)
	s.setFlash(r, flash{
		Title:   "Connection created: " + label,
		Message: "Scan or paste this into the app now. It is shown once and never stored here.",
		Secret:  uri,
		QR:      template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
	})
	http.Redirect(w, r, "/identities/"+id.ID, http.StatusSeeOther)
}

func (s *Server) connectionRevoke(w http.ResponseWriter, r *http.Request) {
	conn, err := s.o.Core.Store().GetConnection(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	conn.RevokedAt = &now
	if err := s.o.Core.Store().PutConnection(conn); err == nil {
		s.o.Core.PublishIdentities()
		s.setFlash(r, flash{Title: "Revoked", Message: "The app can no longer use this connection."})
	}
	http.Redirect(w, r, "/identities/"+conn.IdentityID, http.StatusSeeOther)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	_, err := s.o.Core.NodeInfo(ctx)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "node": err == nil})
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) settingsUpdate(w http.ResponseWriter, r *http.Request) {
	minutes, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("expiry_minutes")), 10, 64)
	pct, perr := strconv.ParseFloat(strings.TrimSpace(r.FormValue("fee_percent")), 64)
	minSat, merr := strconv.ParseInt(strings.TrimSpace(r.FormValue("fee_min_sat")), 10, 64)
	if perr != nil || merr != nil || math.IsNaN(pct) || pct < 0 || pct > 100 {
		s.setFlash(r, flash{Title: "Settings not saved", Message: "The fee limit needs a percentage and a whole number of sats.", Error: true})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	st := store.Settings{
		RouteHints:           r.FormValue("route_hints") == "on",
		SelfPay:              r.FormValue("self_pay") == "on",
		InvoiceExpirySeconds: minutes * 60,
		FeeLimitPPM:          int64(math.Round(pct * 10_000)),
		FeeLimitMinMsat:      minSat * 1000,
	}
	if err := s.o.Core.UpdateSettings(st); err != nil {
		s.setFlash(r, flash{Title: "Settings not saved", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Settings saved", Message: "New invoices and payments use them at once; no restart."})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) sendingLowerCaps(w http.ResponseWriter, r *http.Request) {
	maxPay, _ := strconv.ParseInt(r.FormValue("max_pay_sat"), 10, 64)
	max24, _ := strconv.ParseInt(r.FormValue("max_24h_sat"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.o.Core.LowerCaps(ctx, maxPay*1000, max24*1000); err != nil {
		s.setFlash(r, flash{Title: "Caps not changed", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Caps lowered", Message: "The guard now enforces the new limits."})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) sendingDisable(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.o.Core.DisableSending(ctx); err != nil {
		s.setFlash(r, flash{Title: "Not disabled", Message: err.Error(), Error: true})
	} else {
		s.setFlash(r, flash{Title: "Sending disabled", Message: "The spend credential is gone. Re-enable it with the Authorize Sending action in StartOS."})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

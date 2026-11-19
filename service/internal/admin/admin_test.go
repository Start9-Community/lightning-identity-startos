package admin

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
	"github.com/lundog/lightning-identity-startos/service/internal/pw"
)

// The templates are parsed at construction but executed only per request, so
// this walks every page once against a core with no LND behind it.
func TestPagesRender(t *testing.T) {
	dir := t.TempDir()
	svc, err := core.New(core.Config{DataDir: filepath.Join(dir, "core"), CredentialsDir: filepath.Join(dir, "cred"), IdentitiesDir: filepath.Join(dir, "ids"),
		GuardSocket: filepath.Join(dir, "g.sock"), EdgeSocket: filepath.Join(dir, "e.sock"), LNDRestURL: "https://127.0.0.1:1", LNDCAFile: filepath.Join(dir, "missing.pem"),
		BaseURL: "https://pay.example", RelayURL: "wss://pay.example/relay", Log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	hash, _ := pw.Hash("hunter2hunter2", []byte("0123456789abcdef"))
	srv, err := New(Options{Core: svc, NWC: nwc.New(svc, slog.Default()), PasswordHash: hash, Log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("GET %s: %d, want %d\n%s", path, rec.Code, want, rec.Body.String())
		}
		return rec
	}
	post := func(path string, form url.Values, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("POST %s: %d, want %d\n%s", path, rec.Code, want, rec.Body.String())
		}
		return rec
	}

	get("/login", nil, 200)
	get("/", nil, http.StatusSeeOther) // no session → redirect
	post("/login", url.Values{"password": {"wrong"}}, nil, 200)
	rec := post("/login", url.Values{"password": {"hunter2hunter2"}}, nil, http.StatusSeeOther)
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}
	// No page may depend on script: the content security policy allows none,
	// so an inline handler (the onsubmit="return confirm(...)" these forms
	// once carried) silently never runs and the form just submits.
	pages := map[string]string{}
	page := func(path string) string {
		t.Helper()
		body := get(path, session, 200).Body.String()
		pages[path] = body
		for _, bad := range []string{"<script", " onsubmit=", " onclick=", "javascript:"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Errorf("%s contains %q, which the page's content security policy blocks", path, bad)
			}
		}
		return body
	}
	dash := page("/")
	if !strings.Contains(dash, "No identities yet") || !strings.Contains(dash, `href="/system"`) {
		t.Errorf("empty dashboard lacks its hint or the System link")
	}
	sys := page("/system")
	for _, want := range []string{"Public endpoints", "LND node", "Guard", "wss://pay.example/relay", `<a href="/">← Dashboard</a>`} {
		if !strings.Contains(sys, want) {
			t.Errorf("system page lacks %q", want)
		}
	}
	if newIdentity := page("/identities/new"); !strings.Contains(newIdentity, `<a href="/">← Dashboard</a>`) {
		t.Errorf("the new-identity page has no way back")
	}
	rec = post("/identities", url.Values{"name": {"alice"}, "display_name": {"Alice"}, "min_sat": {"1"}, "max_sat": {"100000"}, "comment_allowed": {"100"}}, session, http.StatusSeeOther)
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/identities/") {
		t.Fatalf("create redirected to %q", loc)
	}
	idPage := page(loc)
	for _, want := range []string{`<a href="/">← Dashboard</a>`, `action="` + loc + `/delete"`, "Yes, delete this identity", `<details class="confirm danger"><summary>Delete identity</summary>`} {
		if !strings.Contains(idPage, want) {
			t.Errorf("identity page lacks %q", want)
		}
	}
	// The result of creating it is shown once, with a way to put it away.
	if !strings.Contains(idPage, `<a class="mut" href="">Dismiss</a>`) && strings.Contains(idPage, `class="card flash`) {
		t.Errorf("a result is shown with nothing to dismiss it")
	}
	// The dashboard leads with the identities, one link each.
	dash = page("/")
	if i, j := strings.Index(dash, "<h2>Identities</h2>"), strings.Index(dash, "<h2>Liquidity</h2>"); i < 0 || j < 0 || i > j {
		t.Errorf("identities should come before liquidity on the dashboard (%d, %d)", i, j)
	}
	if n := strings.Count(dash, `href="`+loc+`"`); n != 1 {
		t.Errorf("the dashboard links to the identity %d times, want once", n)
	}
	for _, gone := range []string{"<h2>Node</h2>", "<h2>Guard</h2>", "Caveats", "manage</a>"} {
		if strings.Contains(dash, gone) {
			t.Errorf("the dashboard still carries %q, which belongs on the System page or nowhere", gone)
		}
	}
	post(loc+"/connections", url.Values{"label": {"phone"}, "m_get_info": {"on"}, "m_pay_invoice": {"on"}, "budget_sat": {"10000"}, "budget_period": {"weekly"}}, session, http.StatusSeeOther)
	body := page(loc)
	if !strings.Contains(body, `<a class="btn" href="">Done</a>`) {
		t.Errorf("the connection string is shown with no way to put it away")
	}
	if again := page(loc); strings.Contains(again, "nostr&#43;walletconnect://") {
		t.Errorf("the connection string was shown a second time")
	}
	if !strings.Contains(body, "nostr&#43;walletconnect://") || !strings.Contains(body, "pay_invoice") || !strings.Contains(body, `src="data:image/png;base64,`) {
		i := strings.Index(body, "<main>")
		t.Fatalf("connection page should show the URI once and the permission:\n%s", body[i:min(len(body), i+1500)])
	}
	// A cross-site POST is refused even with a session.
	req := httptest.NewRequest("POST", loc+"/delete", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST got %d", rr.Code)
	}
}

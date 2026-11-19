package edge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
)

// get makes one request as the OS proxy delivers it: the client's address
// is the X-Forwarded-For value.
func get(s *Server, method, path, clientIP string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if clientIP != "" {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

// The scan seen on a live node: one address asking for /.env, /.git/config
// and a hundred more in a few seconds. It must be cut off after
// MissesPerMinute misses, for everything, while other clients carry on.
func TestScannerIsBlocked(t *testing.T) {
	s, _, _ := testServer(t)
	now := time.Now()
	s.abuse.now = func() time.Time { return now }
	const scanner, visitor = "45.148.10.201", "203.0.113.7"

	for i := 0; i < MissesPerMinute; i++ {
		if rec := get(s, "GET", fmt.Sprintf("/.env.%d", i), scanner); rec.Code != http.StatusNotFound {
			t.Fatalf("probe %d: got %d before the limit, want 404", i, rec.Code)
		}
	}
	// The next miss is still answered (it is the one that tips the count)...
	if rec := get(s, "GET", "/.git/config", scanner); rec.Code != http.StatusNotFound {
		t.Fatalf("tipping probe: %d", rec.Code)
	}
	// ...and from then on the address gets nothing, real pages included.
	for _, p := range []string{"/.aws/credentials", "/", "/.well-known/lnurlp/alice", "/health"} {
		rec := get(s, "GET", p, scanner)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s after the block: got %d, want 429", p, rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: a block should say when to come back", p)
		}
	}
	// Someone else is untouched.
	if rec := get(s, "GET", "/.well-known/lnurlp/alice", visitor); rec.Code != http.StatusOK {
		t.Fatalf("another client during the block: %d", rec.Code)
	}
	// The block ends.
	now = now.Add(BlockFor + time.Second)
	if rec := get(s, "GET", "/.well-known/lnurlp/alice", scanner); rec.Code != http.StatusOK {
		t.Fatalf("after the block expired: %d", rec.Code)
	}
}

// A real client causes the odd 404 (robots.txt, an icon a browser guesses
// at) and must never trip the block.
func TestOccasionalMissesAreFine(t *testing.T) {
	s, _, _ := testServer(t)
	const visitor = "203.0.113.7"
	for i := 0; i < 5; i++ {
		get(s, "GET", "/robots.txt", visitor)
		get(s, "GET", "/apple-touch-icon-precomposed.png", visitor)
		if rec := get(s, "GET", "/.well-known/lnurlp/alice", visitor); rec.Code != http.StatusOK {
			t.Fatalf("round %d: %d", i, rec.Code)
		}
	}
}

// Addresses that are not on the public internet are never blocked: if one
// shows up as the client address, every visitor is behind it.
func TestPrivateAddressesAreNotBlocked(t *testing.T) {
	s, _, _ := testServer(t)
	for _, ip := range []string{"10.0.3.1", "192.168.1.20", "127.0.0.1", "100.64.0.9", "fd00::1"} {
		for i := 0; i < MissesPerMinute*3; i++ {
			if rec := get(s, "GET", "/nope", ip); rec.Code != http.StatusNotFound {
				t.Fatalf("%s request %d: got %d, want 404 (never 429)", ip, i, rec.Code)
			}
		}
	}
}

// An IPv6 scanner rotating through its own /64 is one client.
func TestIPv6ScannerSharesOneBucket(t *testing.T) {
	s, _, _ := testServer(t)
	code := 0
	for i := 0; i < MissesPerMinute+5; i++ {
		code = get(s, "GET", "/nope", fmt.Sprintf("2001:db9:1:2::%x", i+1)).Code
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("after %d misses across one /64: got %d, want 429", MissesPerMinute+5, code)
	}
	if rec := get(s, "GET", "/.well-known/lnurlp/alice", "2001:db9:1:3::1"); rec.Code != http.StatusOK {
		t.Fatalf("a neighbouring /64 was caught too: %d", rec.Code)
	}
}

// The general limit: a minute's worth at once, then refusals.
func TestPerClientLimit(t *testing.T) {
	s, _, _ := testServer(t)
	s2 := New(Options{Identities: s.o.Identities, Core: s.o.Core, Log: s.o.Log})
	const client = "203.0.113.50"
	for i := 0; i < DefaultRequestsPerMinute; i++ {
		if rec := get(s2, "GET", "/.well-known/lnurlp/alice", client); rec.Code != http.StatusOK {
			t.Fatalf("request %d of the allowance: %d", i, rec.Code)
		}
	}
	if rec := get(s2, "GET", "/.well-known/lnurlp/alice", client); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request past the allowance: got %d, want 429", rec.Code)
	}
	if rec := get(s2, "GET", "/.well-known/lnurlp/alice", "203.0.113.51"); rec.Code != http.StatusOK {
		t.Fatalf("another client: %d", rec.Code)
	}
	// Core reaches the embedded relay over loopback with no forwarded
	// header; it is not a client and is never limited.
	for i := 0; i < DefaultRequestsPerMinute*2; i++ {
		r := httptest.NewRequest("GET", "/.well-known/lnurlp/alice", nil)
		r.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		s2.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("loopback request %d: %d", i, rec.Code)
		}
	}
	// ...but a forwarded request that merely claims loopback is a client.
	last := 0
	for i := 0; i < DefaultRequestsPerMinute+1; i++ {
		last = get(s2, "GET", "/.well-known/lnurlp/alice", "127.0.0.1").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("forwarded 127.0.0.1 escaped the limit: %d", last)
	}
}

// The site folder changes while edge runs (the Upload Site and Remove Site
// actions); edge follows it without a restart, and never serves a hidden
// path from it.
func TestSiteFollowsTheFolder(t *testing.T) {
	s, _, _ := testServer(t)
	dir := t.TempDir()
	srv := New(Options{Identities: s.o.Identities, Core: s.o.Core, Log: s.o.Log, SiteDir: dir, RequestsPerMinute: 1000})
	put := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body := func(path string) (int, string) {
		rec := get(srv, "GET", path, "203.0.113.20")
		return rec.Code, rec.Body.String()
	}
	const defaultPage = "Lightning addresses are served from this domain."

	// No index yet: the default page, and nothing else from the folder.
	put("about.html", "about")
	if code, b := body("/"); code != 200 || !strings.Contains(b, defaultPage) {
		t.Fatalf("empty folder: %d %q", code, b)
	}
	if code, _ := body("/about.html"); code != 404 {
		t.Fatalf("a folder without an index served a file: %d", code)
	}

	// The site appears.
	put("index.html", "<h1>hello</h1>")
	put("img/logo.png", "PNG")
	put(".well-known/security.txt", "Contact: mailto:me@example.com")
	put(".env", "SECRET=1")
	put(".git/config", "[core]")
	put("docs/.htaccess", "deny")
	put(".incoming/index.html", "half unpacked")
	for path, want := range map[string]string{"/": "hello", "/about.html": "about", "/img/logo.png": "PNG", "/.well-known/security.txt": "Contact:"} {
		if code, b := body(path); code != 200 || !strings.Contains(b, want) {
			t.Errorf("%s: %d %q, want %q", path, code, b, want)
		}
	}
	for _, path := range []string{"/.env", "/.git/config", "/docs/.htaccess", "/.incoming/index.html", "/.incoming/", "/img/"} {
		if code, b := body(path); code != 404 || strings.Contains(b, "SECRET") {
			t.Errorf("%s: %d %q, want 404", path, code, b)
		}
	}

	// The site is removed.
	if err := os.Remove(filepath.Join(dir, "index.html")); err != nil {
		t.Fatal(err)
	}
	if code, b := body("/"); code != 200 || !strings.Contains(b, defaultPage) {
		t.Fatalf("after removal: %d %q", code, b)
	}
	if code, _ := body("/img/logo.png"); code != 404 {
		t.Fatalf("a removed site still serves files: %d", code)
	}
}

// The site and the default page are read-only documents.
func TestSiteAnswersOnlyGetAndHead(t *testing.T) {
	s, _, _ := testServer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hello</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	withSite := New(Options{Identities: s.o.Identities, Core: s.o.Core, Log: s.o.Log, SiteDir: dir, RequestsPerMinute: 1000})
	for name, srv := range map[string]*Server{"default page": s, "static site": withSite} {
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
			rec := get(srv, m, "/", "203.0.113.9")
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s: %s / = %d (Allow %q), want 405", name, m, rec.Code, rec.Header().Get("Allow"))
			}
		}
		for _, m := range []string{"GET", "HEAD"} {
			if rec := get(srv, m, "/", "203.0.113.10"); rec.Code != http.StatusOK {
				t.Errorf("%s: %s / = %d", name, m, rec.Code)
			}
		}
	}
	if rec := get(withSite, "GET", "/", "203.0.113.10"); !strings.Contains(rec.Body.String(), "hello") {
		t.Errorf("site index not served: %q", rec.Body.String())
	}
	// The default page no longer counts the identities for a stranger.
	if body := get(s, "GET", "/", "203.0.113.10").Body.String(); strings.ContainsAny(body, "0123456789") {
		t.Errorf("default page gives a count away: %q", body)
	}
}

// /health says "ok" and nothing more, and a flood of it reaches core once.
func TestHealthIsMinimalAndCached(t *testing.T) {
	s, _, got := testServer(t)
	for i := 0; i < 30; i++ {
		rec := get(s, "GET", "/health", "203.0.113.11")
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
			t.Fatalf("health %d: %d %q", i, rec.Code, rec.Body.String())
		}
	}
	calls := 0
	for len(got) > 0 {
		if (<-got).Type == "status" {
			calls++
		}
	}
	if calls != 1 {
		t.Fatalf("30 health requests made %d calls into core, want 1", calls)
	}
	// Core gone: 503, still nothing but the flag, and still cached.
	down := New(Options{Identities: s.o.Identities, Core: &ipc.Client{Path: filepath.Join(shortTempDir(t), "absent.sock"), Timeout: time.Second}, Log: s.o.Log, RequestsPerMinute: 1000})
	rec := get(down, "GET", "/health", "203.0.113.11")
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != `{"ok":false}` {
		t.Fatalf("health with core down: %d %q", rec.Code, rec.Body.String())
	}
}

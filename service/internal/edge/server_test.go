package edge

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lundog/lightning-identity-startos/service/internal/identity"
	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnurl"
	"github.com/lundog/lightning-identity-startos/service/internal/zap"
)

func testServer(t *testing.T) (*Server, *identity.Doc, chan ipc.Request) {
	t.Helper()
	dir := t.TempDir()
	zapPK, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	userPK, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	doc := &identity.Doc{Domain: "pay.example", BaseURL: "https://pay.example", RelayURL: "wss://pay.example/relay",
		Identities: []identity.Entry{{Name: "alice", DisplayName: "Alice", ZapPubkey: zapPK, UserPubkey: userPK, NIP05: true, MinMsat: 1000, MaxMsat: 100000, CommentAllowed: 20}}}
	if err := identity.Write(dir, doc); err != nil {
		t.Fatal(err)
	}
	w := identity.NewWatcher(dir)
	sock := filepath.Join(shortTempDir(t), "c.sock")
	got := make(chan ipc.Request, 8)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &ipc.Server{Path: sock, AllowedUIDs: []uint32{uint32(os.Getuid())}, Handler: func(ctx context.Context, req ipc.Request) (any, error) {
		got <- req
		switch req.Type {
		case "create_invoice":
			return map[string]string{"pr": "lnbc1test", "payment_hash": "ab"}, nil
		case "verify_invoice":
			return lnurl.VerifyResponse{Status: "OK", Settled: false, PR: "lnbc1test"}, nil
		case "status":
			return map[string]bool{"ok": true}, nil
		}
		return nil, nil
	}}
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)
	s := New(Options{Identities: w, Core: &ipc.Client{Path: sock, Timeout: time.Second}, Log: slog.Default(), InvoicesPerMinute: 1000, RequestsPerMinute: 1000})
	return s, doc, got
}

func TestLNURLDocument(t *testing.T) {
	s, _, _ := testServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/lnurlp/alice", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var res lnurl.PayResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Tag != "payRequest" || res.Callback != "https://pay.example/lnurlp/alice/callback" || !res.AllowsNostr || res.MinSendable != 1000 {
		t.Fatalf("bad document: %+v", res)
	}
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/lnurlp/nobody", nil))
	if rec.Code != 404 {
		t.Fatalf("unknown name should 404, got %d", rec.Code)
	}
}

func TestCallbackValidationAndForwarding(t *testing.T) {
	s, doc, got := testServer(t)
	// too small
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/lnurlp/alice/callback?amount=10", nil))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for tiny amount, got %d", rec.Code)
	}
	// comment too long
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/lnurlp/alice/callback?amount=5000&comment="+url.QueryEscape("this comment is definitely longer than twenty"), nil))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for long comment, got %d", rec.Code)
	}
	// valid zap
	sk := nostr.GeneratePrivateKey()
	ev := nostr.Event{Kind: zap.KindZapRequest, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"p", doc.Identities[0].UserPubkey}, {"relays", "wss://r"}, {"amount", "5000"}}}
	_ = ev.Sign(sk)
	raw, _ := json.Marshal(ev)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/lnurlp/alice/callback?amount=5000&nostr="+url.QueryEscape(string(raw)), nil))
	if rec.Code != 200 {
		t.Fatalf("zap callback failed %d: %s", rec.Code, rec.Body.String())
	}
	req := <-got
	var p lnurl.CallbackRequest
	_ = json.Unmarshal(req.Params, &p)
	if req.Type != "create_invoice" || p.Identity != "alice" || p.AmountMsat != 5000 || p.ZapRequest == "" {
		t.Fatalf("forwarded badly: %+v", p)
	}
	var res lnurl.CallbackResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.PR != "lnbc1test" || res.Verify != "https://pay.example/lnurlp/alice/verify/ab" {
		t.Fatalf("bad response: %+v", res)
	}
	// forged zap request is refused before reaching core
	ev.Content = "forged"
	raw, _ = json.Marshal(ev)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/lnurlp/alice/callback?amount=5000&nostr="+url.QueryEscape(string(raw)), nil))
	if rec.Code != 400 {
		t.Fatalf("forged zap accepted: %d", rec.Code)
	}
}

func TestNIP05(t *testing.T) {
	s, doc, _ := testServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/nostr.json?name=alice", nil))
	var out struct {
		Names  map[string]string   `json:"names"`
		Relays map[string][]string `json:"relays"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	// No relay hint: our relay is not where the user's events live.
	if out.Names["alice"] != doc.Identities[0].UserPubkey || out.Relays != nil {
		t.Fatalf("bad nip05: %s", rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("NIP-05 needs CORS")
	}
}

func TestUnknownPathsAnd404(t *testing.T) {
	s, _, _ := testServer(t)
	for _, p := range []string{"/admin", "/api/anything", "/.well-known/other"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", p, rec.Code)
		}
	}
}

// shortTempDir is for unix sockets: their path is capped at 104 bytes on
// macOS (108 on Linux) and t.TempDir() on a Mac is longer than that.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "li")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

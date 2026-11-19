package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
)

func testAdmin(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	svc, err := core.New(core.Config{DataDir: filepath.Join(dir, "core"), CredentialsDir: filepath.Join(dir, "cred"), IdentitiesDir: filepath.Join(dir, "ids"),
		GuardSocket: filepath.Join(dir, "g.sock"), EdgeSocket: filepath.Join(dir, "e.sock"), LNDRestURL: "https://127.0.0.1:1", LNDCAFile: filepath.Join(dir, "missing.pem"),
		BaseURL: "https://pay.example", RelayURL: "wss://pay.example/relay", Log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	srv, err := New(Options{Core: svc, NWC: nwc.New(svc, slog.Default()), Log: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// guardWith builds a guard status as core receives it (JSON over the
// socket, so numbers are float64) around one liquidity document.
func guardWith(t *testing.T, liquidity string) map[string]any {
	t.Helper()
	doc := `{"lnd_state":"SERVER_ACTIVE","sending_enabled":false`
	if liquidity != "" {
		doc += `,"liquidity":` + liquidity
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(doc+"}"), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func renderDashboard(t *testing.T, srv *Server, guard map[string]any, guardErr string, balancesMsat int64) string {
	t.Helper()
	data := map[string]any{
		"NodeErr": "not asked in this test", "Guard": guard, "GuardErr": guardErr, "TotalMsat": balancesMsat,
		"Config": srv.o.Core.Config(), "Settings": srv.o.Core.Settings(), "Domain": "pay.example",
		"Liquidity": newLiquidityView(guard, balancesMsat),
	}
	var buf bytes.Buffer
	if err := srv.tmpl.ExecuteTemplate(&buf, "dashboard.html", data); err != nil {
		t.Fatalf("dashboard template: %v", err)
	}
	return buf.String()
}

// The Liquidity card has to say something true in every state the guard can
// report, and warn in the ones that cost the operator money or payments.
func TestDashboardLiquidityStates(t *testing.T) {
	srv := testAdmin(t)
	one := `{"channels":1,"active":1,"can_send_msat":290000000,"can_receive_msat":690000000,"largest_send_msat":290000000,"largest_receive_msat":690000000,
		"list":[{"peer":"Some LSP","pubkey":"03aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899ab","active":true,"unannounced":true,"can_send_msat":290000000,"can_receive_msat":690000000}]}`
	for _, tc := range []struct {
		name      string
		liquidity string
		guardErr  string
		balances  int64
		want      []string
		not       []string
	}{
		{name: "guard down", guardErr: "dial unix: no such file", want: []string{"Unknown until the guard answers"}, not: []string{"Can send"}},
		{name: "not reported yet", want: []string{"has not reported the node's channels yet"}, not: []string{"Can send"}},
		{name: "lnd unreadable", liquidity: `{"error":"could not read channels from LND"}`, want: []string{"Could not read the node's channels: could not read channels from LND."}, not: []string{"no open channels"}},
		{name: "no channels", liquidity: `{"channels":0,"active":0}`, want: []string{"The node has no open channels"}, not: []string{"Can send"}},
		{name: "one healthy channel", liquidity: one, balances: 100_000_000,
			want: []string{"Can send", "290,000 sats", "Can receive", "690,000 sats", `Some LSP <span class="mono mut">03aa11bb…778899ab</span>`, "(unannounced)", "online"},
			not:  []string{`class="warn"`, `<p class="mut">`, "online channel", "pending payments", "could not be paid out"}},
		{name: "balances exceed what can be sent", liquidity: one, balances: 500_000_000,
			want: []string{"Identities hold 500,000 sats, but the node can send about 290,000 sats. 210,000 sats of those balances could not be paid out right now."}},
		{name: "nothing can be received", liquidity: `{"channels":1,"active":1,"can_send_msat":990000000,"can_receive_msat":0,"largest_send_msat":990000000,
			"list":[{"peer":"New channel","active":true,"can_send_msat":990000000,"can_receive_msat":0}]}`,
			want: []string{"No room to receive", "990,000 sats"}},
		{name: "one of two offline", liquidity: `{"channels":2,"active":1,"can_send_msat":290000000,"can_receive_msat":690000000,"offline_send_msat":90000000,
			"largest_send_msat":290000000,"largest_receive_msat":690000000,
			"list":[{"peer":"A","active":true,"can_send_msat":290000000,"can_receive_msat":690000000},{"peer":"B","active":false,"can_send_msat":90000000,"can_receive_msat":90000000}]}`,
			want: []string{"1 of 2 channels is offline; the 90,000 sats on your side of it cannot be sent until the peer is back.", "offline"}},
		{name: "peer with no alias on record", liquidity: `{"channels":1,"active":1,"can_send_msat":1000,"can_receive_msat":1000,"largest_send_msat":1000,"largest_receive_msat":1000,
			"list":[{"peer":"","pubkey":"02ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","active":true,"can_send_msat":1000,"can_receive_msat":1000}]}`,
			want: []string{`<td><span class="mono">02ffeedd…33221100</span></td>`}},
		{name: "an alias is shown as text, never as markup", liquidity: `{"channels":1,"active":1,"can_send_msat":1000,"can_receive_msat":1000,
			"list":[{"peer":"<script>alert(1)</script>","pubkey":"02ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","active":true,"can_send_msat":1000,"can_receive_msat":1000}]}`,
			want: []string{"&lt;script&gt;alert(1)&lt;/script&gt;"}, not: []string{"<script>alert(1)"}},
		{name: "all offline", liquidity: `{"channels":1,"active":0,"offline_send_msat":290000000,"list":[{"peer":"A","active":false,"can_send_msat":290000000,"can_receive_msat":690000000}]}`,
			want: []string{"Every channel is offline"}, not: []string{"No room to receive"}},
		{name: "several channels", liquidity: `{"channels":2,"active":2,"can_send_msat":436000000,"can_receive_msat":906000000,"largest_send_msat":387000000,"largest_receive_msat":887000000,"unsettled_msat":1500000,
			"list":[{"peer":"big","active":true,"can_send_msat":387000000,"can_receive_msat":887000000},{"peer":"small","active":true,"can_send_msat":49000000,"can_receive_msat":19000000}]}`,
			want: []string{`<p class="mut">1,500 sats in pending payments.</p>`, "387,000 sats", "49,000 sats"}, not: []string{"online channel", "unsplit", "reserve"}},
	} {
		html := renderDashboard(t, srv, guardWith(t, tc.liquidity), tc.guardErr, tc.balances)
		card := html[strings.Index(html, "<h2>Liquidity</h2>"):]
		card = card[:strings.Index(card, "<h2>Sending</h2>")]
		for _, w := range tc.want {
			if !strings.Contains(card, w) {
				t.Errorf("%s: missing %q in:\n%s", tc.name, w, card)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(card, n) {
				t.Errorf("%s: should not say %q", tc.name, n)
			}
		}
	}
}

func TestGroupDigits(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 12345: "12,345", 123456: "123,456", 1234567: "1,234,567", 2100000000000000: "2,100,000,000,000,000", -1234: "-1,234"} {
		if got := groupDigits(n); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", n, got, want)
		}
	}
}

// The icon is served without a login (the login page shows it), as SVG, and
// may be cached; every page links it. The embedded copy must be the package
// icon at the repository root.
func TestIcon(t *testing.T) {
	srv := testAdmin(t)
	for _, path := range []string{"/icon.svg", "/favicon.ico"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(rec.Body.String(), "<svg") {
			t.Fatalf("GET %s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
			t.Errorf("GET %s: Cache-Control %q", path, cc)
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if body := rec.Body.String(); !strings.Contains(body, `<link rel="icon" type="image/svg+xml" href="/icon.svg">`) || !strings.Contains(body, `<img src="/icon.svg"`) {
		t.Errorf("the page does not use the icon:\n%.600s", body)
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "..", "icon.svg"))
	if err != nil {
		t.Skipf("package icon not found beside the module (%v); cannot compare", err)
	}
	if !bytes.Equal(root, iconSVG) {
		t.Fatal("internal/admin/static/icon.svg differs from icon.svg at the repository root: copy the root icon over it")
	}
}

func TestSatsUnit(t *testing.T) {
	for n, want := range map[int64]string{0: "0 sats", 1: "1 sat", 2: "2 sats", 21: "21 sats", 1000: "1,000 sats", 1290000: "1,290,000 sats"} {
		if got := sats(n); got != want {
			t.Errorf("sats(%d) = %q, want %q", n, got, want)
		}
	}
	if got := signedSats(-1500); got != "−1,500 sats" {
		t.Errorf("signedSats(-1500) = %q", got)
	}
	if got := signedSats(-1); got != "−1 sat" {
		t.Errorf("signedSats(-1) = %q", got)
	}
}

// Moving the plumbing to the System page must not hide a fault: whatever
// stops the service is named on the dashboard until it clears.
func TestProblems(t *testing.T) {
	healthy := map[string]any{"lnd_state": "SERVER_ACTIVE", "receive_expires": "2031-01-02T03:04:05Z", "sending_enabled": true,
		"middleware_registered": true, "spend_expires": "2031-01-02T03:04:05Z"}
	synced := &lnd.Info{SyncedToChain: true}
	if got := problems(healthy, nil, synced, nil); len(got) != 0 {
		t.Errorf("a healthy service reports problems: %q", got)
	}
	receiveOnly := map[string]any{"receive_expires": "2031-01-02T03:04:05Z", "sending_enabled": false, "spend_expires": "0001-01-01T00:00:00Z"}
	if got := problems(receiveOnly, nil, synced, nil); len(got) != 0 {
		t.Errorf("receive-only is not a problem: %q", got)
	}
	for _, tc := range []struct {
		name     string
		guard    map[string]any
		guardErr error
		node     *lnd.Info
		nodeErr  error
		want     []string
	}{
		{"guard down", nil, errors.New("dial unix: no such file"), synced, nil, []string{"The guard is not answering (dial unix: no such file)"}},
		{"guard error", map[string]any{"receive_expires": "2031-01-02T03:04:05Z", "last_error": "lnd: wallet locked"}, nil, synced, nil, []string{"The guard reports: lnd: wallet locked"}},
		// A time that was never set arrives as year 1, not as nothing.
		{"nothing baked", map[string]any{"receive_expires": "0001-01-01T00:00:00Z"}, nil, synced, nil, []string{"no receive credential yet"}},
		{"nothing baked, key absent", map[string]any{}, nil, synced, nil, []string{"no receive credential yet"}},
		{"middleware missing", map[string]any{"receive_expires": "2031-01-02T03:04:05Z", "sending_enabled": true, "spend_expires": "2031-01-02T03:04:05Z"}, nil, synced, nil, []string{"caps check is not registered"}},
		{"no spend credential", map[string]any{"receive_expires": "2031-01-02T03:04:05Z", "sending_enabled": true, "middleware_registered": true, "spend_expires": "0001-01-01T00:00:00Z"}, nil, synced, nil, []string{"no spend credential yet"}},
		{"lnd unreachable", healthy, nil, nil, errors.New("connection refused"), []string{"LND is not reachable (connection refused)"}},
		{"not synced", healthy, nil, &lnd.Info{}, nil, []string{"not synced to the chain"}},
	} {
		got := problems(tc.guard, tc.guardErr, tc.node, tc.nodeErr)
		if len(got) != len(tc.want) {
			t.Errorf("%s: %q, want %d problem(s)", tc.name, got, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: %q, want it to contain %q", tc.name, got[i], w)
			}
		}
	}
}

func TestSystemView(t *testing.T) {
	var guard map[string]any
	if err := json.Unmarshal([]byte(`{"lnd_state":"SERVER_ACTIVE","admin_macaroon_ok":true,"sending_enabled":true,"middleware_registered":true,
		"receive_expires":"2031-01-02T03:04:05Z","receive_methods":["/lnrpc.Lightning/AddInvoice"],"receive_caveats":["time-before 2031-01-02T03:04:05Z"],
		"spend_expires":"0001-01-01T00:00:00Z","spend_methods":["/routerrpc.Router/SendPaymentV2"]}`), &guard); err != nil {
		t.Fatal(err)
	}
	v := newSystemView(guard)
	if !v.Receive.Baked || v.Receive.Expires != "2031-01-02 03:04 UTC" || len(v.Receive.Methods) != 1 || len(v.Receive.Caveats) != 1 {
		t.Errorf("receive credential: %+v", v.Receive)
	}
	if v.Spend.Baked || v.Spend.Expires != "" || len(v.Spend.Methods) != 1 {
		t.Errorf("a spend credential that was never baked shows as baked: %+v", v.Spend)
	}
	if v.LNDState != "SERVER_ACTIVE" || !v.AdminOK || !v.SendingEnabled || !v.Middleware {
		t.Errorf("view: %+v", v)
	}
	if empty := newSystemView(nil); empty.Receive.Baked || empty.AdminOK {
		t.Errorf("no status at all: %+v", empty)
	}
}

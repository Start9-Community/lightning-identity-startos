package lnd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A wallet app supplies the invoice, and the invoice goes into a URL path.
// Nothing but a plain invoice may reach LND: a crafted string must not be
// able to address a different endpoint with this client's macaroon.
func TestInvoiceAndHashCannotSteerTheRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, http: srv.Client()}
	ctx := context.Background()

	for _, bad := range []string{
		"../getinfo",
		"lnbc1/../../v1/getinfo",
		"lnbc1xyz?x=/../v1/invoices/subscribe",
		"lnbc1xyz%2f..%2f..%2fv1%2fgetinfo",
		"lnbc1xyz#frag",
		"lnbc1 xyz",
		"https://example.com/lnbc1xyz",
		"",
	} {
		if _, err := c.DecodePayReq(ctx, bad); err == nil {
			t.Errorf("DecodePayReq accepted %q", bad)
		}
	}
	for _, bad := range []string{
		strings.Repeat("g", 64), // not hex
		"../../v1/getinfo" + strings.Repeat("0", 48),
		strings.Repeat("A", 64), // uppercase is not what we store
		"abcd",
	} {
		if _, err := c.LookupInvoice(ctx, bad); err == nil {
			t.Errorf("LookupInvoice accepted %q", bad)
		}
		if _, err := c.TrackPayment(ctx, bad); err == nil {
			t.Errorf("TrackPayment accepted %q", bad)
		}
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("crafted input reached LND: %v", seen)
	}

	// The honest forms still work and land where they should.
	if _, err := c.DecodePayReq(ctx, "LIGHTNING:LNBC1PVJLUEZ"+strings.Repeat("Q", 20)); err != nil {
		t.Fatalf("uppercase invoice with scheme: %v", err)
	}
	if _, err := c.LookupInvoice(ctx, strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("hex hash: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "/v1/payreq/lnbc1pvjluez") || seen[1] != "/v1/invoice/"+strings.Repeat("ab", 32)+"?" {
		t.Fatalf("requests: %v", seen)
	}
}

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mac "gopkg.in/macaroon.v2"
)

// fakeLND is enough of LND's REST API for the three processes to run end to
// end: state, getinfo, bake, invoices, lookup, a subscribe stream and the
// channel balance. It records the macaroons it saw so tests can assert what
// the guard baked and what core used.
type fakeLND struct {
	srv     *httptest.Server
	caFile  string
	rootKey []byte
	leaf    tls.Certificate
	grpc    *fakeGRPC

	mu       sync.Mutex
	invoices map[string]*fakeInvoiceRow
	addIdx   int64
	settled  chan *fakeInvoiceRow
	seenMacs []string

	// What /v1/channels answers, and how often it was asked.
	channels     []map[string]any
	channelsErr  bool
	channelCalls int

	// How often each invoice was looked up, and how often the invoice
	// stream was opened.
	lookups    map[string]int
	subscribes int
}

type fakeInvoiceRow struct {
	Hash      []byte
	Preimage  []byte
	ValueMsat int64
	DescHash  []byte
	Memo      string
	AddIndex  int64
	Settled   bool
	Canceled  bool
	SettleIdx int64
	Created   int64
	SettledAt int64 // unix seconds; 0 means "now" when asked
}

// bolt11 renders the fake's decodable invoice form for this row.
func (i *fakeInvoiceRow) bolt11() string {
	return fmt.Sprintf("lnfakex%dx%s", i.ValueMsat, hex.EncodeToString(i.Hash))
}

func newFakeLND(t *testing.T, dir string) *fakeLND {
	t.Helper()
	f := &fakeLND{invoices: map[string]*fakeInvoiceRow{}, settled: make(chan *fakeInvoiceRow, 16), rootKey: []byte("fake-root-key")}
	// CA + leaf for 127.0.0.1
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "lnd"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	f.caFile = filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"state": "SERVER_ACTIVE"})
	})
	mux.HandleFunc("/v1/getinfo", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		writeJSON(w, map[string]any{"identity_pubkey": strings.Repeat("ab", 33), "alias": "fake", "color": "#ff9900", "block_height": 900000, "block_hash": "00", "synced_to_chain": true, "chains": []map[string]string{{"chain": "bitcoin", "network": "mainnet"}}})
	})
	// Channels are readable with the admin macaroon only, as on a real node
	// where the baked credentials carry no channel permission.
	mux.HandleFunc("/v1/channels", func(w http.ResponseWriter, r *http.Request) {
		m, ok := f.authMac(w, r)
		if !ok {
			return
		}
		if string(m.Id()) != "admin" {
			http.Error(w, `{"code":7,"message":"permission denied"}`, 403)
			return
		}
		f.mu.Lock()
		f.channelCalls++
		chs, bad := f.channels, f.channelsErr
		f.mu.Unlock()
		if bad {
			http.Error(w, `{"code":2,"message":"channel db unavailable"}`, 500)
			return
		}
		// Like LND, name the peers only when the caller asked.
		out := []map[string]any{}
		for _, c := range chs {
			row := map[string]any{}
			for k, v := range c {
				if k == "peer_alias" && r.URL.Query().Get("peer_alias_lookup") != "true" {
					continue
				}
				row[k] = v
			}
			out = append(out, row)
		}
		writeJSON(w, map[string]any{"channels": out})
	})
	mux.HandleFunc("/v1/macaroon", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var body struct {
			Permissions []struct{ Entity, Action string } `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Permissions) == 0 || body.Permissions[0].Entity != "uri" {
			http.Error(w, `{"code":3,"message":"bad permissions"}`, 400)
			return
		}
		m, _ := mac.New(f.rootKey, []byte("baked"), "lnd", mac.V2)
		raw, _ := m.MarshalBinary()
		writeJSON(w, map[string]string{"macaroon": hex.EncodeToString(raw)})
	})
	mux.HandleFunc("/v1/invoices", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var body struct {
			ValueMsat       string `json:"value_msat"`
			DescriptionHash string `json:"description_hash"`
			Memo            string `json:"memo"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		pre := make([]byte, 32)
		_, _ = rand.Read(pre)
		h := sha256.Sum256(pre)
		dh, _ := base64.StdEncoding.DecodeString(body.DescriptionHash)
		var v int64
		fmt.Sscan(body.ValueMsat, &v)
		f.mu.Lock()
		f.addIdx++
		inv := &fakeInvoiceRow{Hash: h[:], Preimage: pre, ValueMsat: v, DescHash: dh, Memo: body.Memo, AddIndex: f.addIdx, Created: time.Now().Unix()}
		f.invoices[hex.EncodeToString(h[:])] = inv
		f.mu.Unlock()
		writeJSON(w, map[string]any{"r_hash": base64.StdEncoding.EncodeToString(h[:]), "payment_request": inv.bolt11(), "add_index": fmt.Sprint(inv.AddIndex)})
	})
	mux.HandleFunc("/v1/invoice/", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		hash := strings.TrimPrefix(r.URL.Path, "/v1/invoice/")
		f.mu.Lock()
		inv := f.invoices[hash]
		if f.lookups == nil {
			f.lookups = map[string]int{}
		}
		f.lookups[hash]++
		f.mu.Unlock()
		if inv == nil {
			http.Error(w, `{"code":5,"message":"unable to locate invoice"}`, 404)
			return
		}
		writeJSON(w, inv.json())
	})
	mux.HandleFunc("/v2/invoices/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var body struct {
			PaymentHash string `json:"payment_hash"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := base64.StdEncoding.DecodeString(body.PaymentHash)
		f.mu.Lock()
		defer f.mu.Unlock()
		inv := f.invoices[hex.EncodeToString(raw)]
		switch {
		case inv == nil:
			http.Error(w, `{"code":5,"message":"unable to locate invoice"}`, 404)
		case inv.Settled:
			http.Error(w, `{"code":9,"message":"invoice already settled"}`, 400)
		default:
			inv.Canceled = true
			writeJSON(w, map[string]any{})
		}
	})
	mux.HandleFunc("/v1/payreq/", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		pr, err := decodeFakeInvoice(strings.TrimPrefix(r.URL.Path, "/v1/payreq/"))
		if err != nil {
			http.Error(w, `{"code":3,"message":"`+err.Error()+`"}`, 400)
			return
		}
		writeJSON(w, map[string]any{"destination": strings.Repeat("cd", 33), "payment_hash": pr.hash, "num_msat": fmt.Sprint(pr.msat), "timestamp": fmt.Sprint(time.Now().Unix()), "expiry": "3600", "description": "fake"})
	})
	mux.HandleFunc("/v2/router/send", func(w http.ResponseWriter, r *http.Request) {
		if f.grpc == nil {
			http.Error(w, `{"code":16,"message":"no middleware registered for custom caveat"}`, 401)
			return
		}
		f.grpc.sendPaymentREST(w, r)
	})
	mux.HandleFunc("/v2/router/track/", func(w http.ResponseWriter, r *http.Request) {
		if f.grpc == nil {
			http.Error(w, `{"code":16,"message":"no middleware registered for custom caveat"}`, 401)
			return
		}
		f.grpc.trackPaymentREST(w, r)
	})
	mux.HandleFunc("/v1/invoices/subscribe", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		fl, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fl.Flush()
		f.mu.Lock()
		f.subscribes++
		f.mu.Unlock()
		for {
			select {
			case <-r.Context().Done():
				return
			case inv := <-f.settled:
				b, _ := json.Marshal(map[string]any{"result": inv.json()})
				_, _ = w.Write(append(b, '\n'))
				fl.Flush()
			}
		}
	})
	f.leaf = tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.leaf}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// checkMacaroon verifies a hex macaroon the way LND would (signature chain
// over the root key, except for the unbaked "admin" test macaroon) and
// returns it parsed.
func (f *fakeLND) checkMacaroon(h string) (*mac.Macaroon, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("bad macaroon")
	}
	var m mac.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, errors.New("bad macaroon")
	}
	if string(m.Id()) != "admin" {
		if err := m.Verify(f.rootKey, func(c string) error { return nil }, nil); err != nil {
			return nil, errors.New("macaroon verification failed")
		}
		// A custom caveat with no middleware registered is rejected outright,
		// as LND does.
		if hasCustomCaveat(&m) && (f.grpc == nil || f.grpc.registered() == "") {
			return nil, errors.New("no middleware registered for custom caveat")
		}
	}
	f.mu.Lock()
	f.seenMacs = append(f.seenMacs, h)
	f.mu.Unlock()
	return &m, nil
}

func (f *fakeLND) authMac(w http.ResponseWriter, r *http.Request) (*mac.Macaroon, bool) {
	h := r.Header.Get("Grpc-Metadata-macaroon")
	if h == "" {
		http.Error(w, `{"code":16,"message":"expected 1 macaroon, got 0"}`, 401)
		return nil, false
	}
	m, err := f.checkMacaroon(h)
	if err != nil {
		http.Error(w, `{"code":16,"message":"`+err.Error()+`"}`, 401)
		return nil, false
	}
	return m, true
}

func (f *fakeLND) auth(w http.ResponseWriter, r *http.Request) bool {
	_, ok := f.authMac(w, r)
	return ok
}

func (f *fakeLND) adminMacaroonFile(t *testing.T, dir string) string {
	m, _ := mac.New(f.rootKey, []byte("admin"), "lnd", mac.V2)
	raw, _ := m.MarshalBinary()
	p := filepath.Join(dir, "admin.macaroon")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fakeLND) settle(hash string) {
	f.mu.Lock()
	inv := f.invoices[hash]
	if inv != nil && !inv.Settled {
		inv.Settled = true
		inv.SettleIdx = inv.AddIndex
	}
	f.mu.Unlock()
	if inv != nil {
		f.settled <- inv
	}
}

// settleSilently marks an invoice paid without telling the invoice stream:
// what a stream that has stopped delivering looks like from outside. The
// settlement is dated in the past, as one the stream had time to deliver.
func (f *fakeLND) settleSilently(hash string, ago time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if inv := f.invoices[hash]; inv != nil && !inv.Settled {
		inv.Settled = true
		inv.SettleIdx = inv.AddIndex
		inv.SettledAt = time.Now().Add(-ago).Unix()
	}
}

func (f *fakeLND) counts(hash string) (lookups, subscribes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups[hash], f.subscribes
}

func (i *fakeInvoiceRow) json() map[string]any {
	state := "OPEN"
	if i.Settled {
		state = "SETTLED"
	} else if i.Canceled {
		state = "CANCELED"
	}
	// LND returns the preimage of its own invoices whatever their state.
	out := map[string]any{
		"r_hash": base64.StdEncoding.EncodeToString(i.Hash), "r_preimage": base64.StdEncoding.EncodeToString(i.Preimage), "value_msat": fmt.Sprint(i.ValueMsat), "state": state, "settled": i.Settled,
		"add_index": fmt.Sprint(i.AddIndex), "settle_index": fmt.Sprint(i.SettleIdx), "creation_date": fmt.Sprint(i.Created),
		"payment_request": i.bolt11(), "description_hash": base64.StdEncoding.EncodeToString(i.DescHash), "memo": i.Memo,
	}
	if i.Settled {
		out["amt_paid_msat"] = fmt.Sprint(i.ValueMsat)
		at := i.SettledAt
		if at == 0 {
			at = time.Now().Unix()
		}
		out["settle_date"] = fmt.Sprint(at)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

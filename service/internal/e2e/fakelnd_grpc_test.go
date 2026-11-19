package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	mac "gopkg.in/macaroon.v2"

	lnrpc "github.com/lundog/lightning-identity-startos/service/internal/lndrpc"
	"github.com/lundog/lightning-identity-startos/service/internal/lndrpc/routerrpc"
)

// fakeGRPC is the gRPC face of the fake LND: GetInfo, BakeMacaroon,
// DecodePayReq and the RPC middleware stream. Its REST sibling routes
// SendPaymentV2 through the registered middleware exactly as LND does — a
// stream_auth intercept, a request intercept, then a response intercept per
// Payment update — so the guard's caps are exercised for real.
type fakeGRPC struct {
	lnrpc.UnimplementedLightningServer
	lnd  *fakeLND
	addr string

	mu       sync.Mutex
	stream   lnrpc.Lightning_RegisterRPCMiddlewareServer
	caveat   string // registered custom caveat name
	nextMsg  uint64
	nextReq  uint64
	pending  map[uint64]chan *lnrpc.InterceptFeedback
	payments map[string]*fakePayment
}

type fakePayment struct {
	Hash     string
	Preimage string
	Msat     int64
	FeeMsat  int64
	Status   string
	Created  time.Time
	ReqID    uint64 // middleware request id, for the late response intercept
	Guarded  bool
}

// fakeRouter is the slice of routerrpc the guard uses with the admin
// macaroon: looking a payment up by hash.
type fakeRouter struct {
	routerrpc.UnimplementedRouterServer
	g *fakeGRPC
}

func (r *fakeRouter) TrackPaymentV2(req *routerrpc.TrackPaymentRequest, stream grpc.ServerStreamingServer[lnrpc.Payment]) error {
	if err := r.g.authGRPC(stream.Context()); err != nil {
		return err
	}
	r.g.mu.Lock()
	p := r.g.payments[hex.EncodeToString(req.GetPaymentHash())]
	var out *lnrpc.Payment
	if p != nil {
		out = &lnrpc.Payment{PaymentHash: p.Hash, ValueMsat: p.Msat, FeeMsat: p.FeeMsat, PaymentPreimage: p.Preimage, CreationTimeNs: p.Created.UnixNano(),
			Status: lnrpc.Payment_PaymentStatus(lnrpc.Payment_PaymentStatus_value[p.Status])}
	}
	r.g.mu.Unlock()
	if out == nil {
		return status.Error(codes.NotFound, "payment isn't initiated")
	}
	return stream.Send(out)
}

// release resolves a held payment the way the recipient of a hold invoice
// would: settle it (or fail it) long after the sender stopped waiting.
func (g *fakeGRPC) release(hash string, succeed bool) {
	g.mu.Lock()
	p := g.payments[hash]
	if p == nil || p.Status != "IN_FLIGHT" {
		g.mu.Unlock()
		return
	}
	p.Status = "SUCCEEDED"
	st := lnrpc.Payment_SUCCEEDED
	if !succeed {
		p.Status, st = "FAILED", lnrpc.Payment_FAILED
	}
	pay := &lnrpc.Payment{PaymentHash: p.Hash, ValueMsat: p.Msat, FeeMsat: p.FeeMsat, PaymentPreimage: p.Preimage, Status: st}
	reqID, guarded := p.ReqID, p.Guarded
	g.mu.Unlock()
	if guarded {
		raw, _ := proto.Marshal(pay)
		_, _ = g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{MethodFullUri: "/routerrpc.Router/SendPaymentV2", StreamRpc: true, TypeName: "lnrpc.Payment", Serialized: raw}}})
	}
}

// trackPaymentREST is GET /v2/router/track/{payment_hash}: the current state
// of a payment this node initiated, or NOT_FOUND. The hash is base64 in the
// path, as grpc-gateway encodes bytes fields.
func (g *fakeGRPC) trackPaymentREST(w http.ResponseWriter, r *http.Request) {
	m, ok := g.lnd.authMac(w, r)
	if !ok {
		return
	}
	if hasCustomCaveat(m) {
		g.mu.Lock()
		g.nextReq++
		reqID := g.nextReq
		g.mu.Unlock()
		fb, err := g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, CustomCaveatCondition: g.customCondition(m), InterceptType: &lnrpc.RPCMiddlewareRequest_StreamAuth{StreamAuth: &lnrpc.StreamAuth{MethodFullUri: "/routerrpc.Router/TrackPaymentV2"}}})
		if err != nil {
			http.Error(w, `{"code":16,"message":"`+err.Error()+`"}`, 401)
			return
		}
		if fb.GetError() != "" {
			http.Error(w, `{"code":7,"message":"`+fb.GetError()+`"}`, 403)
			return
		}
	}
	enc, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/v2/router/track/"))
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(enc)
	}
	if err != nil || len(raw) != 32 {
		http.Error(w, `{"code":3,"message":"invalid payment hash"}`, 400)
		return
	}
	g.mu.Lock()
	p := g.payments[hex.EncodeToString(raw)]
	var line []byte
	if p != nil {
		line, _ = json.Marshal(map[string]any{"result": map[string]any{
			"payment_hash": p.Hash, "payment_preimage": p.Preimage, "value_msat": fmt.Sprint(p.Msat), "fee_msat": fmt.Sprint(p.FeeMsat),
			"status": p.Status, "creation_time_ns": fmt.Sprint(p.Created.UnixNano()),
		}})
	}
	g.mu.Unlock()
	if p == nil {
		http.Error(w, `{"code":5,"message":"payment isn't initiated"}`, 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(line, '\n'))
}

func (f *fakeLND) startGRPC(t *testing.T, leaf tls.Certificate) *fakeGRPC {
	t.Helper()
	g := &fakeGRPC{lnd: f, pending: map[uint64]chan *lnrpc.InterceptFeedback{}, payments: map[string]*fakePayment{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.addr = ln.Addr().String()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{leaf}})))
	lnrpc.RegisterLightningServer(srv, g)
	routerrpc.RegisterRouterServer(srv, &fakeRouter{g: g})
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	f.grpc = g
	return g
}

func (g *fakeGRPC) registered() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stream == nil {
		return ""
	}
	return g.caveat
}

func (g *fakeGRPC) authGRPC(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("macaroon")
	if len(vals) == 0 {
		return status.Error(codes.Unauthenticated, "expected 1 macaroon, got 0")
	}
	if _, err := g.lnd.checkMacaroon(vals[0]); err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	return nil
}

func (g *fakeGRPC) GetInfo(ctx context.Context, _ *lnrpc.GetInfoRequest) (*lnrpc.GetInfoResponse, error) {
	if err := g.authGRPC(ctx); err != nil {
		return nil, err
	}
	return &lnrpc.GetInfoResponse{IdentityPubkey: strings.Repeat("ab", 33), Alias: "fake", BlockHeight: 900000, SyncedToChain: true}, nil
}

func (g *fakeGRPC) BakeMacaroon(ctx context.Context, req *lnrpc.BakeMacaroonRequest) (*lnrpc.BakeMacaroonResponse, error) {
	if err := g.authGRPC(ctx); err != nil {
		return nil, err
	}
	m, _ := mac.New(g.lnd.rootKey, []byte("baked"), "lnd", mac.V2)
	raw, _ := m.MarshalBinary()
	return &lnrpc.BakeMacaroonResponse{Macaroon: hex.EncodeToString(raw)}, nil
}

func (g *fakeGRPC) DecodePayReq(ctx context.Context, req *lnrpc.PayReqString) (*lnrpc.PayReq, error) {
	if err := g.authGRPC(ctx); err != nil {
		return nil, err
	}
	pr, err := decodeFakeInvoice(req.GetPayReq())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &lnrpc.PayReq{Destination: strings.Repeat("cd", 33), PaymentHash: pr.hash, NumMsat: pr.msat, Timestamp: time.Now().Unix(), Expiry: 3600, Description: "fake"}, nil
}

func (g *fakeGRPC) RegisterRPCMiddleware(stream lnrpc.Lightning_RegisterRPCMiddlewareServer) error {
	if err := g.authGRPC(stream.Context()); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil || reg.GetCustomMacaroonCaveatName() == "" {
		return status.Error(codes.InvalidArgument, "first message must be a registration")
	}
	g.mu.Lock()
	g.stream, g.caveat = stream, reg.GetCustomMacaroonCaveatName()
	g.mu.Unlock()
	if err := stream.Send(&lnrpc.RPCMiddlewareRequest{InterceptType: &lnrpc.RPCMiddlewareRequest_RegComplete{RegComplete: true}}); err != nil {
		return err
	}
	defer func() {
		g.mu.Lock()
		if g.stream == stream {
			g.stream = nil
		}
		g.mu.Unlock()
	}()
	for {
		res, err := stream.Recv()
		if err != nil {
			return err
		}
		g.mu.Lock()
		ch := g.pending[res.GetRefMsgId()]
		delete(g.pending, res.GetRefMsgId())
		g.mu.Unlock()
		if ch != nil {
			ch <- res.GetFeedback()
		}
	}
}

// intercept sends one intercept message to the middleware and waits for its
// feedback, as LND does (with its intercept timeout).
func (g *fakeGRPC) intercept(req *lnrpc.RPCMiddlewareRequest) (*lnrpc.InterceptFeedback, error) {
	g.mu.Lock()
	stream := g.stream
	if stream == nil {
		g.mu.Unlock()
		return nil, errors.New("no middleware registered for custom caveat")
	}
	g.nextMsg++
	req.MsgId = g.nextMsg
	ch := make(chan *lnrpc.InterceptFeedback, 1)
	g.pending[req.MsgId] = ch
	g.mu.Unlock()
	if err := stream.Send(req); err != nil {
		return nil, err
	}
	select {
	case fb := <-ch:
		return fb, nil
	case <-time.After(3 * time.Second):
		return nil, errors.New("middleware intercept timeout")
	}
}

// customCondition extracts the condition of the registered custom caveat
// from a macaroon, or "" when the macaroon carries none.
func (g *fakeGRPC) customCondition(m *mac.Macaroon) string {
	g.mu.Lock()
	name := g.caveat
	g.mu.Unlock()
	for _, c := range m.Caveats() {
		if len(c.VerificationId) > 0 {
			continue
		}
		parts := strings.SplitN(string(c.Id), " ", 3)
		if len(parts) == 3 && parts[0] == "lnd-custom" && parts[1] == name {
			return parts[2]
		}
	}
	return ""
}

func hasCustomCaveat(m *mac.Macaroon) bool {
	for _, c := range m.Caveats() {
		if len(c.VerificationId) == 0 && strings.HasPrefix(string(c.Id), "lnd-custom ") {
			return true
		}
	}
	return false
}

// sendPaymentREST is the REST handler for POST /v2/router/send. It mimics
// LND's path: macaroon check, middleware stream_auth + request intercepts for
// a macaroon that carries the custom caveat, the payment, and a response
// intercept carrying the terminal lnrpc.Payment.
func (g *fakeGRPC) sendPaymentREST(w http.ResponseWriter, r *http.Request) {
	m, ok := g.lnd.authMac(w, r)
	if !ok {
		return
	}
	var body struct {
		PaymentRequest string `json:"payment_request"`
		AmtMsat        string `json:"amt_msat"`
		FeeLimitMsat   string `json:"fee_limit_msat"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	pr, err := decodeFakeInvoice(body.PaymentRequest)
	if err != nil {
		http.Error(w, `{"code":3,"message":"`+err.Error()+`"}`, 400)
		return
	}
	amt := pr.msat
	if amt == 0 {
		amt, _ = strconv.ParseInt(body.AmtMsat, 10, 64)
	}
	feeLimit, _ := strconv.ParseInt(body.FeeLimitMsat, 10, 64)

	g.mu.Lock()
	g.nextReq++
	reqID := g.nextReq
	g.mu.Unlock()
	const method = "/routerrpc.Router/SendPaymentV2"
	if hasCustomCaveat(m) {
		cond := g.customCondition(m)
		fb, err := g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, CustomCaveatCondition: cond, InterceptType: &lnrpc.RPCMiddlewareRequest_StreamAuth{StreamAuth: &lnrpc.StreamAuth{MethodFullUri: method}}})
		if err != nil {
			http.Error(w, `{"code":16,"message":"`+err.Error()+`"}`, 401)
			return
		}
		if fb.GetError() != "" {
			http.Error(w, `{"code":7,"message":"`+fb.GetError()+`"}`, 403)
			return
		}
		reqAmt, _ := strconv.ParseInt(body.AmtMsat, 10, 64) // the request as the caller sent it
		spr, _ := proto.Marshal(&routerrpc.SendPaymentRequest{PaymentRequest: body.PaymentRequest, AmtMsat: reqAmt, FeeLimitMsat: feeLimit})
		fb, err = g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, CustomCaveatCondition: cond, InterceptType: &lnrpc.RPCMiddlewareRequest_Request{Request: &lnrpc.RPCMessage{MethodFullUri: method, StreamRpc: true, TypeName: "routerrpc.SendPaymentRequest", Serialized: spr}}})
		if err != nil {
			http.Error(w, `{"code":16,"message":"`+err.Error()+`"}`, 401)
			return
		}
		if fb.GetError() != "" {
			http.Error(w, `{"code":7,"message":"`+fb.GetError()+`"}`, 403)
			return
		}
	}

	// LND refuses a second payment of a hash it has paid or is paying. The
	// refusal comes from the handler, after the middleware accepted the
	// request, so the middleware hears about it as an error response.
	g.mu.Lock()
	prev := g.payments[pr.hash]
	g.mu.Unlock()
	if prev != nil && (prev.Status == "SUCCEEDED" || prev.Status == "IN_FLIGHT") {
		msg := "invoice is already paid"
		if prev.Status == "IN_FLIGHT" {
			msg = "payment is in transition"
		}
		if hasCustomCaveat(m) {
			_, _ = g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{MethodFullUri: method, StreamRpc: true, TypeName: "error", Serialized: []byte(msg), IsError: true}}})
		}
		http.Error(w, `{"code":6,"message":"`+msg+`"}`, 409)
		return
	}

	// "Pay": success unless the invoice says to fail — or to hold, where the
	// recipient accepts the HTLC and sits on it: the payment is IN_FLIGHT on
	// the node and the caller hears nothing until release() or it gives up.
	pre := make([]byte, 32)
	_, _ = rand.Read(pre)
	pay := &lnrpc.Payment{PaymentHash: pr.hash, ValueMsat: amt, FeeMsat: 1000, PaymentPreimage: hex.EncodeToString(pre), Status: lnrpc.Payment_SUCCEEDED}
	if pr.fail {
		pay.Status, pay.FailureReason = lnrpc.Payment_FAILED, lnrpc.PaymentFailureReason_FAILURE_REASON_NO_ROUTE
	}
	rec := &fakePayment{Hash: pr.hash, Preimage: pay.PaymentPreimage, Msat: amt, FeeMsat: 1000, Status: pay.Status.String(), Created: time.Now(), ReqID: reqID, Guarded: hasCustomCaveat(m)}
	if pr.hold {
		rec.Status = "IN_FLIGHT"
	}
	g.mu.Lock()
	g.payments[pr.hash] = rec
	g.mu.Unlock()
	if pr.hold {
		// no_inflight_updates: nothing is written; the stream just stays open.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-r.Context().Done()
		// The caller hung up. LND tells the middleware the stream ended in
		// an error; the payment itself is untouched and still in flight.
		if hasCustomCaveat(m) {
			_, _ = g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{MethodFullUri: method, StreamRpc: true, TypeName: "error", Serialized: []byte("context canceled"), IsError: true}}})
		}
		return
	}
	if hasCustomCaveat(m) {
		raw, _ := proto.Marshal(pay)
		_, _ = g.intercept(&lnrpc.RPCMiddlewareRequest{RequestId: reqID, InterceptType: &lnrpc.RPCMiddlewareRequest_Response{Response: &lnrpc.RPCMessage{MethodFullUri: method, StreamRpc: true, TypeName: "lnrpc.Payment", Serialized: raw}}})
	}
	w.Header().Set("Content-Type", "application/json")
	line, _ := json.Marshal(map[string]any{"result": map[string]any{
		"payment_hash": pay.PaymentHash, "payment_preimage": pay.PaymentPreimage, "value_msat": fmt.Sprint(pay.ValueMsat),
		"fee_msat": fmt.Sprint(pay.FeeMsat), "status": pay.Status.String(), "failure_reason": pay.FailureReason.String(),
	}})
	_, _ = w.Write(append(line, '\n'))
}

// fakeInvoice is "lnfakex<msat>x<hash32hex>[xfail|xhold]": lowercase
// alphanumerics only, like a real bolt11, with "x" (not a hex digit) as the
// separator.
type fakeInvoice struct {
	msat int64
	hash string
	fail bool
	hold bool
}

func makeFakeInvoice(msat int64, fail bool) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	h := sha256.Sum256(b[:])
	s := fmt.Sprintf("lnfakex%dx%s", msat, hex.EncodeToString(h[:]))
	if fail {
		s += "xfail"
	}
	return s
}

func makeHoldInvoice(msat int64) string { return makeFakeInvoice(msat, false) + "xhold" }

func decodeFakeInvoice(s string) (*fakeInvoice, error) {
	parts := strings.Split(s, "x")
	if len(parts) < 3 || parts[0] != "lnfake" {
		return nil, errors.New("not a fake invoice")
	}
	msat, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, err
	}
	out := &fakeInvoice{msat: msat, hash: parts[2]}
	if len(parts) > 3 {
		out.fail, out.hold = parts[3] == "fail", parts[3] == "hold"
	}
	return out, nil
}

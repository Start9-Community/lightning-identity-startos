package guard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lundog/lightning-identity-startos/service/internal/lndgrpc"
	lnrpc "github.com/lundog/lightning-identity-startos/service/internal/lndrpc"
	"github.com/lundog/lightning-identity-startos/service/internal/lndrpc/routerrpc"
)

// MiddlewareName is both the registered middleware name and the custom caveat
// name every spend credential carries (`lnd-custom <MiddlewareName> <nonce>`).
// LND routes every request bearing that caveat to this middleware, and
// rejects such requests outright while no middleware is registered.
const MiddlewareName = "lightning-identity-guard"

// Methods the spend credential grants. SendPaymentV2 is the one that moves
// money and the one the pricer understands; the other two are read-only.
const (
	methodSendPayment  = "/routerrpc.Router/SendPaymentV2"
	methodTrackPayment = "/routerrpc.Router/TrackPaymentV2"
	methodDecodePayReq = "/lnrpc.Lightning/DecodePayReq"
)

// SpendMethods is the URI set baked into the spend credential.
var SpendMethods = []string{methodSendPayment, methodTrackPayment, methodDecodePayReq}

// readOnlySpendMethods may pass without pricing. Anything else intercepted
// under our caveat is rejected: adding a URI to the credential without a
// pricer fails closed.
var readOnlySpendMethods = map[string]bool{methodTrackPayment: true, methodDecodePayReq: true}

// UnsureInterval is how often unsure reservations are looked up on LND. A
// var so tests can shorten it.
var UnsureInterval = time.Minute

// reservationTTL bounds how long an in-flight payment holds budget before it
// is committed as spent (the conservative outcome if LND never tells us).
const reservationTTL = 15 * time.Minute

type reservation struct {
	msat int64
	at   time.Time
	hash string
	// unsure marks a reservation whose stream ended in an error or that was
	// restored after a restart: only LND's own record can say what became
	// of the payment.
	unsure bool
}

// runMiddleware keeps a middleware registered with LND for as long as ctx
// lives, reconnecting after every failure. While it is down the spend
// credential is dead — LND rejects a custom caveat with no middleware — so the
// only job here is to come back.
func (g *Guard) runMiddleware(ctx context.Context) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		err := g.serveMiddleware(ctx)
		g.setMiddleware(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			g.log.Warn("guard: middleware stream ended", "err", err)
		}
		sleep(ctx, backoff)
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (g *Guard) serveMiddleware(ctx context.Context) error {
	adminHex, err := g.adminMacaroon()
	if err != nil {
		return err
	}
	conn, err := lndgrpc.Dial(ctx, g.cfg.LNDGRPCAddress, g.cfg.LNDCAFile, adminHex)
	if err != nil {
		return err
	}
	defer conn.Close()
	stream, err := conn.Lightning.RegisterRPCMiddleware(ctx)
	if err != nil {
		return err
	}
	reg := &lnrpc.RPCMiddlewareResponse{MiddlewareMessage: &lnrpc.RPCMiddlewareResponse_Register{Register: &lnrpc.MiddlewareRegistration{
		MiddlewareName:           MiddlewareName,
		CustomMacaroonCaveatName: MiddlewareName,
		ReadOnlyMode:             false,
	}}}
	if err := stream.Send(reg); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	if !first.GetRegComplete() {
		return errors.New("LND did not confirm middleware registration")
	}
	g.setMiddleware(true)
	g.log.Info("guard: middleware registered", "name", MiddlewareName)
	// Unsure reservations (stream errors, a restart) are looked up on LND
	// now and every minute, on their own goroutine: the stream loop below
	// must never wait on anything but LND's next message.
	rctx, stopResolver := context.WithCancel(ctx)
	defer stopResolver()
	go func() {
		t := time.NewTicker(UnsureInterval)
		defer t.Stop()
		for {
			g.resolveAllUnsure(rctx, conn)
			select {
			case <-rctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	select {
	case g.kick <- struct{}{}:
	default:
	}
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return errors.New("stream closed by LND")
		}
		if err != nil {
			return err
		}
		feedback := g.intercept(ctx, conn, req)
		res := &lnrpc.RPCMiddlewareResponse{
			RefMsgId:          req.GetMsgId(),
			MiddlewareMessage: &lnrpc.RPCMiddlewareResponse_Feedback{Feedback: feedback},
		}
		if err := stream.Send(res); err != nil {
			return err
		}
	}
}

func (g *Guard) setMiddleware(up bool) {
	g.update(func(s *Status) { s.MiddlewareRegistered = up })
}

// maxMsat is every bitcoin that will ever exist, in millisatoshi. No honest
// amount or fee limit exceeds it, and two of them cannot overflow int64.
const maxMsat = int64(21_000_000) * 100_000_000 * 1000

func reject(msg string) *lnrpc.InterceptFeedback { return &lnrpc.InterceptFeedback{Error: msg} }

func accept() *lnrpc.InterceptFeedback { return &lnrpc.InterceptFeedback{} }

// intercept decides one message. Every decision defaults to rejection.
func (g *Guard) intercept(ctx context.Context, conn *lndgrpc.Conn, req *lnrpc.RPCMiddlewareRequest) *lnrpc.InterceptFeedback {
	switch {
	case req.GetStreamAuth() != nil:
		if err := g.authorized(req.GetCustomCaveatCondition()); err != nil {
			return reject(err.Error())
		}
		m := req.GetStreamAuth().GetMethodFullUri()
		if m == methodSendPayment || readOnlySpendMethods[m] {
			return accept()
		}
		return reject("guard: stream " + m + " is not permitted by this credential")
	case req.GetRequest() != nil:
		if err := g.authorized(req.GetCustomCaveatCondition()); err != nil {
			return reject(err.Error())
		}
		msg := req.GetRequest()
		m := msg.GetMethodFullUri()
		if readOnlySpendMethods[m] {
			return accept()
		}
		if m != methodSendPayment {
			return reject("guard: " + m + " is not permitted by this credential")
		}
		return g.priceSendPayment(ctx, conn, req.GetRequestId(), msg)
	case req.GetResponse() != nil:
		g.settleFromResponse(ctx, conn, req.GetRequestId(), req.GetResponse())
		return accept()
	default:
		return accept()
	}
}

// authorized checks the caveat condition against the current nonce and the
// latch: a credential from an earlier enabled period, or any credential
// while sending is off, is refused here even though LND accepted its
// signature.
func (g *Guard) authorized(condition string) error {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	if !g.state.SendingEnabled {
		return errors.New("guard: sending is disabled")
	}
	if condition == "" || condition != g.state.Nonce {
		return errors.New("guard: credential does not belong to the current sending authorization")
	}
	return nil
}

// priceSendPayment learns what a SendPaymentV2 would cost, applies the caps,
// and reserves the amount against the window.
func (g *Guard) priceSendPayment(ctx context.Context, conn *lndgrpc.Conn, requestID uint64, msg *lnrpc.RPCMessage) *lnrpc.InterceptFeedback {
	if msg.GetTypeName() != "routerrpc.SendPaymentRequest" {
		return reject("guard: unexpected message type " + msg.GetTypeName())
	}
	var sp routerrpc.SendPaymentRequest
	if err := proto.Unmarshal(msg.GetSerialized(), &sp); err != nil {
		return reject("guard: cannot decode payment request")
	}
	if strings.TrimSpace(sp.GetPaymentRequest()) == "" {
		return reject("guard: only invoice payments are permitted (no keysend)")
	}
	dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	pr, err := conn.Lightning.DecodePayReq(dctx, &lnrpc.PayReqString{PayReq: sp.GetPaymentRequest()})
	if err != nil {
		return reject("guard: invoice could not be decoded")
	}
	// Every number in the request is the caller's, and the caller may be a
	// compromised core: nothing is added or multiplied before it is known
	// to be a non-negative amount that could exist. With each term bounded
	// by maxMsat, the sums below cannot wrap int64.
	for name, v := range map[string]int64{
		"amt": sp.GetAmt(), "amt_msat": sp.GetAmtMsat(), "fee_limit_sat": sp.GetFeeLimitSat(), "fee_limit_msat": sp.GetFeeLimitMsat(),
		"invoice amount": pr.GetNumMsat(),
	} {
		if v < 0 || v > maxMsat {
			return reject("guard: " + name + " is out of range")
		}
	}
	if (sp.GetAmt() != 0 && sp.GetAmtMsat() != 0) || (sp.GetFeeLimitSat() != 0 && sp.GetFeeLimitMsat() != 0) {
		return reject("guard: sat and msat fields are mutually exclusive")
	}
	if sp.GetAmt() > maxMsat/1000 || sp.GetFeeLimitSat() > maxMsat/1000 {
		return reject("guard: amount is out of range")
	}
	amount := pr.GetNumMsat()
	if amount == 0 {
		amount = sp.GetAmtMsat() + sp.GetAmt()*1000 // one of them is zero
	} else if sp.GetAmtMsat() != 0 || sp.GetAmt() != 0 {
		return reject("guard: an amount may only be given for an invoice without one")
	}
	if amount <= 0 {
		return reject("guard: payment amount is unknown")
	}
	feeLimit := sp.GetFeeLimitMsat() + sp.GetFeeLimitSat()*1000 // one of them is zero
	total := amount + feeLimit
	if total <= 0 || total < amount {
		return reject("guard: payment total is out of range")
	}

	now := time.Now()
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	if g.state.MaxPaymentMsat <= 0 || g.state.Max24hMsat <= 0 {
		return reject("guard: spending caps are zero")
	}
	if total > g.state.MaxPaymentMsat {
		return reject(fmt.Sprintf("guard: payment of %d msat (with fee limit) exceeds the per-payment cap of %d msat", total, g.state.MaxPaymentMsat))
	}
	g.expireReservationsLocked(now)
	used := g.spentLocked(now) + g.reservedLocked()
	if used+total > g.state.Max24hMsat {
		return reject(fmt.Sprintf("guard: payment of %d msat would exceed the 24-hour cap (%d of %d msat already used)", total, used, g.state.Max24hMsat))
	}
	g.reservations[requestID] = &reservation{msat: total, at: now, hash: pr.GetPaymentHash()}
	if err := g.saveStateLocked(); err != nil {
		// A reservation that cannot be written down could be forgotten by a
		// restart while the payment is in flight: refuse rather than risk it.
		delete(g.reservations, requestID)
		g.log.Error("guard: cannot persist reservation", "err", err)
		return reject("guard: cannot record the payment; refusing it")
	}
	g.log.Info("guard: payment reserved", "request_id", requestID, "msat", total, "hash", pr.GetPaymentHash())
	return accept()
}

func (g *Guard) reservedLocked() int64 {
	var sum int64
	for _, r := range g.reservations {
		sum += r.msat
	}
	return sum
}

// expireReservationsLocked commits reservations LND never resolved: a payment
// we lost track of counts as spent, never as free.
func (g *Guard) expireReservationsLocked(now time.Time) {
	for id, r := range g.reservations {
		if now.Sub(r.at) > reservationTTL {
			g.state.Ledger = append(g.state.Ledger, LedgerEntry{At: r.at, Msat: r.msat, Hash: r.hash})
			delete(g.reservations, id)
			_ = g.saveStateLocked()
			g.log.Warn("guard: reservation expired, committed as spent", "request_id", id, "msat", r.msat)
		}
	}
}

// settleFromResponse resolves a reservation from the Payment updates LND
// streams back: SUCCEEDED commits amount + fee actually paid, FAILED releases.
//
// An error on the stream is not a verdict. LND sends one when the payment
// was refused before it began, but also when the caller merely hung up —
// and a caller that pays a hold invoice and hangs up has a payment in
// flight that the recipient can still settle. Releasing on an error would
// let that be repeated without limit. So an error only marks the
// reservation unsure, and LND's own payment record decides.
func (g *Guard) settleFromResponse(ctx context.Context, conn *lndgrpc.Conn, requestID uint64, msg *lnrpc.RPCMessage) {
	if msg.GetIsError() {
		g.stateMu.Lock()
		r, ok := g.reservations[requestID]
		if ok {
			r.unsure = true
		}
		g.stateMu.Unlock()
		if ok {
			g.resolveUnsure(ctx, conn, requestID)
		}
		return
	}
	if msg.GetTypeName() != "lnrpc.Payment" {
		return
	}
	var p lnrpc.Payment
	if err := proto.Unmarshal(msg.GetSerialized(), &p); err != nil {
		return
	}
	switch p.GetStatus() {
	case lnrpc.Payment_SUCCEEDED:
		g.commit(requestID, p.GetValueMsat()+p.GetFeeMsat(), p.GetPaymentHash())
	case lnrpc.Payment_FAILED:
		g.release(requestID, p.GetFailureReason().String())
	}
}

func (g *Guard) commit(requestID uint64, msat int64, hash string) {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	r, ok := g.reservations[requestID]
	if !ok {
		return
	}
	delete(g.reservations, requestID)
	if msat <= 0 {
		msat = r.msat
	}
	g.state.Ledger = append(g.state.Ledger, LedgerEntry{At: time.Now().UTC(), Msat: msat, Hash: hash})
	if err := g.saveStateLocked(); err != nil {
		g.log.Error("guard: save ledger", "err", err)
	}
	g.log.Info("guard: payment committed", "request_id", requestID, "msat", msat, "hash", hash)
}

func (g *Guard) release(requestID uint64, why string) {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	if r, ok := g.reservations[requestID]; ok {
		delete(g.reservations, requestID)
		_ = g.saveStateLocked()
		g.log.Info("guard: payment released", "request_id", requestID, "msat", r.msat, "why", why)
	}
}

// resolveUnsure asks LND what became of the payment behind an unsure
// reservation. Only a definite answer changes anything: never started or
// failed releases it, succeeded commits what was paid. In flight, or no
// answer, leaves it reserved — and a reservation left alone ages into the
// ledger as spent (expireReservationsLocked), never as free.
func (g *Guard) resolveUnsure(ctx context.Context, conn *lndgrpc.Conn, requestID uint64) {
	g.stateMu.Lock()
	r, ok := g.reservations[requestID]
	var hash string
	var at time.Time
	if ok {
		hash, at = r.hash, r.at
	}
	g.stateMu.Unlock()
	if !ok || conn == nil {
		return
	}
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 32 {
		return
	}
	tctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var p *lnrpc.Payment
	stream, err := conn.Router.TrackPaymentV2(tctx, &routerrpc.TrackPaymentRequest{PaymentHash: raw})
	if err == nil {
		p, err = stream.Recv()
	}
	switch {
	case status.Code(err) == codes.NotFound:
		g.release(requestID, "LND never started this payment")
	case err != nil:
		g.log.Warn("guard: cannot look up an unresolved payment; it stays reserved", "request_id", requestID, "hash", hash, "err", err)
	case p.GetCreationTimeNs() > 0 && time.Unix(0, p.GetCreationTimeNs()).Before(at.Add(-5*time.Second)):
		// LND's record for this hash predates the request: the request was
		// refused ("already paid", "in transition") and paid nothing.
		g.release(requestID, "LND refused it; an earlier payment of this invoice exists")
	case p.GetStatus() == lnrpc.Payment_SUCCEEDED:
		g.commit(requestID, p.GetValueMsat()+p.GetFeeMsat(), hash)
	case p.GetStatus() == lnrpc.Payment_FAILED:
		g.release(requestID, p.GetFailureReason().String())
	default:
		g.log.Info("guard: payment still in flight after its stream ended; it stays reserved", "request_id", requestID, "hash", hash, "status", p.GetStatus().String())
	}
}

// resolveAllUnsure runs resolveUnsure over every unsure reservation: once
// the middleware is up (restored reservations) and then periodically.
func (g *Guard) resolveAllUnsure(ctx context.Context, conn *lndgrpc.Conn) {
	g.stateMu.Lock()
	var ids []uint64
	for id, r := range g.reservations {
		if r.unsure {
			ids = append(ids, id)
		}
	}
	g.stateMu.Unlock()
	for _, id := range ids {
		g.resolveUnsure(ctx, conn, id)
	}
}

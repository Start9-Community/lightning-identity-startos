package lnd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Int64 decodes LND's string-encoded 64-bit integers (and plain numbers).
type Int64 int64

func (i *Int64) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	if len(s) > 1 && s[0] == '"' {
		var err error
		s, err = strconv.Unquote(s)
		if err != nil {
			return err
		}
	}
	if s == "" {
		*i = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*i = Int64(v)
	return nil
}

func (i Int64) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatInt(int64(i), 10))), nil
}

// Bytes decodes LND's base64 byte fields.
type Bytes []byte

func (b *Bytes) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if s == "" {
		*b = nil
		return nil
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

// Hex renders the bytes as lowercase hex (payment hashes, preimages).
func (b Bytes) Hex() string { return hex.EncodeToString(b) }

// Info is the subset of GetInfo this service reads.
type Info struct {
	IdentityPubkey string   `json:"identity_pubkey"`
	Alias          string   `json:"alias"`
	Color          string   `json:"color"`
	BlockHeight    int64    `json:"block_height"`
	BlockHash      string   `json:"block_hash"`
	SyncedToChain  bool     `json:"synced_to_chain"`
	SyncedToGraph  bool     `json:"synced_to_graph"`
	Version        string   `json:"version"`
	Chains         []Chain  `json:"chains"`
	URIs           []string `json:"uris"`
}

// Chain names the network LND runs on ("bitcoin"/"mainnet").
type Chain struct {
	Chain   string `json:"chain"`
	Network string `json:"network"`
}

// GetInfo calls /v1/getinfo.
func (c *Client) GetInfo(ctx context.Context) (*Info, error) {
	var out Info
	if err := c.do(ctx, "GET", "/v1/getinfo", nil, &out, 15*time.Second); err != nil {
		return nil, err
	}
	return &out, nil
}

// Channel is the subset of ListChannels the guard summarises into the
// operator's liquidity view. Balances are in satoshis.
type Channel struct {
	Active            bool                `json:"active"` // the peer is connected and the channel usable
	RemotePubkey      string              `json:"remote_pubkey"`
	PeerAlias         string              `json:"peer_alias"`
	Capacity          Int64               `json:"capacity"`
	LocalBalance      Int64               `json:"local_balance"`
	RemoteBalance     Int64               `json:"remote_balance"`
	UnsettledBalance  Int64               `json:"unsettled_balance"`
	Private           bool                `json:"private"`
	LocalConstraints  *ChannelConstraints `json:"local_constraints"`
	RemoteConstraints *ChannelConstraints `json:"remote_constraints"`
}

// ChannelConstraints carries the one constraint the summary uses: the
// reserve that side must keep and can never spend.
type ChannelConstraints struct {
	ChanReserveSat Int64 `json:"chan_reserve_sat"`
}

// ListChannels calls /v1/channels: every open channel. It needs a macaroon
// with offchain read permission; of this service's processes only the guard
// holds one. LND leaves peer_alias empty unless asked for it
// (peer_alias_lookup, off by default for speed), so it is asked.
func (c *Client) ListChannels(ctx context.Context) ([]Channel, error) {
	var out struct {
		Channels []Channel `json:"channels"`
	}
	if err := c.do(ctx, "GET", "/v1/channels?peer_alias_lookup=true", nil, &out, 15*time.Second); err != nil {
		return nil, err
	}
	return out.Channels, nil
}

// WalletState mirrors /v1/state: NON_EXISTING, LOCKED, UNLOCKED, RPC_ACTIVE,
// SERVER_ACTIVE, WAITING_TO_START.
type WalletState struct {
	State string `json:"state"`
}

// GetState calls /v1/state, which needs no macaroon.
func (c *Client) GetState(ctx context.Context) (string, error) {
	var out WalletState
	if err := c.do(ctx, "GET", "/v1/state", nil, &out, 10*time.Second); err != nil {
		return "", err
	}
	return out.State, nil
}

// AddInvoiceRequest is the body of POST /v1/invoices.
type AddInvoiceRequest struct {
	Memo            string `json:"memo,omitempty"`
	ValueMsat       Int64  `json:"value_msat"`
	DescriptionHash Bytes  `json:"description_hash,omitempty"`
	Expiry          Int64  `json:"expiry,omitempty"`
	Private         bool   `json:"private,omitempty"`
}

// AddInvoiceResponse is LND's answer to AddInvoice.
type AddInvoiceResponse struct {
	RHash          Bytes  `json:"r_hash"`
	PaymentRequest string `json:"payment_request"`
	AddIndex       Int64  `json:"add_index"`
	PaymentAddr    Bytes  `json:"payment_addr"`
}

// AddInvoice calls POST /v1/invoices.
func (c *Client) AddInvoice(ctx context.Context, req AddInvoiceRequest) (*AddInvoiceResponse, error) {
	var out AddInvoiceResponse
	if err := c.do(ctx, "POST", "/v1/invoices", req, &out, 20*time.Second); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelInvoice cancels an open invoice (invoicesrpc). Used by self-pay so an
// internally settled invoice can never also be paid over Lightning. Fails if
// the invoice is already settled, which is exactly the race it guards.
func (c *Client) CancelInvoice(ctx context.Context, paymentHash []byte) error {
	body := map[string]any{"payment_hash": base64.StdEncoding.EncodeToString(paymentHash)}
	return c.do(ctx, "POST", "/v2/invoices/cancel", body, &struct{}{}, 15*time.Second)
}

// Invoice is the subset of lnrpc.Invoice this service reads.
type Invoice struct {
	Memo            string `json:"memo"`
	RPreimage       Bytes  `json:"r_preimage"`
	RHash           Bytes  `json:"r_hash"`
	ValueMsat       Int64  `json:"value_msat"`
	Settled         bool   `json:"settled"`
	CreationDate    Int64  `json:"creation_date"`
	SettleDate      Int64  `json:"settle_date"`
	PaymentRequest  string `json:"payment_request"`
	DescriptionHash Bytes  `json:"description_hash"`
	Expiry          Int64  `json:"expiry"`
	AddIndex        Int64  `json:"add_index"`
	SettleIndex     Int64  `json:"settle_index"`
	AmtPaidMsat     Int64  `json:"amt_paid_msat"`
	State           string `json:"state"` // OPEN, SETTLED, CANCELED, ACCEPTED
}

// LookupInvoice calls GET /v1/invoice/{hash} with the payment hash as hex.
func (c *Client) LookupInvoice(ctx context.Context, paymentHashHex string) (*Invoice, error) {
	if !IsPaymentHash(paymentHashHex) {
		return nil, fmt.Errorf("payment hash must be 32 bytes hex")
	}
	var out Invoice
	if err := c.do(ctx, "GET", "/v1/invoice/"+paymentHashHex, nil, &out, 15*time.Second); err != nil {
		return nil, err
	}
	return &out, nil
}

// SubscribeInvoices streams invoice updates from the given indices (0 = all
// future events only, as LND defines it) until ctx ends or the stream breaks.
func (c *Client) SubscribeInvoices(ctx context.Context, addIndex, settleIndex int64, fn func(*Invoice) error) error {
	path := fmt.Sprintf("/v1/invoices/subscribe?add_index=%d&settle_index=%d", addIndex, settleIndex)
	return c.stream(ctx, path, func(raw json.RawMessage) error {
		var inv Invoice
		if err := json.Unmarshal(raw, &inv); err != nil {
			return err
		}
		return fn(&inv)
	})
}

// Permission is one entry of a BakeMacaroon request. For URI-scoped
// permissions the entity is "uri" and the action the full method name.
type Permission struct {
	Entity string `json:"entity"`
	Action string `json:"action"`
}

// BakeMacaroon calls POST /v1/macaroon and returns the macaroon as hex.
// Caveats are not part of the request; they are added client-side by the
// macaroon package so that every credential carries the same policy.
func (c *Client) BakeMacaroon(ctx context.Context, perms []Permission) (string, error) {
	body := struct {
		Permissions              []Permission `json:"permissions"`
		RootKeyID                Int64        `json:"root_key_id"`
		AllowExternalPermissions bool         `json:"allow_external_permissions"`
	}{Permissions: perms}
	var out struct {
		Macaroon string `json:"macaroon"`
	}
	if err := c.do(ctx, "POST", "/v1/macaroon", body, &out, 20*time.Second); err != nil {
		return "", err
	}
	return out.Macaroon, nil
}

// URIPermissions builds a URI-scoped permission list from method names.
func URIPermissions(methods ...string) []Permission {
	out := make([]Permission, 0, len(methods))
	for _, m := range methods {
		out = append(out, Permission{Entity: "uri", Action: m})
	}
	return out
}

// PayReq is the subset of DecodePayReq this service reads.
type PayReq struct {
	Destination string `json:"destination"`
	PaymentHash string `json:"payment_hash"`
	NumMsat     Int64  `json:"num_msat"`
	Timestamp   Int64  `json:"timestamp"`
	Expiry      Int64  `json:"expiry"`
	Description string `json:"description"`
	DescHash    string `json:"description_hash"`
}

// DecodePayReq calls GET /v1/payreq/{invoice}.
func (c *Client) DecodePayReq(ctx context.Context, bolt11 string) (*PayReq, error) {
	var out PayReq
	// The invoice goes into the URL path, and it comes from a wallet app:
	// anything but a plain bech32 string could address a different LND
	// endpoint with this client's macaroon.
	bolt11, err := NormalizeBolt11(bolt11)
	if err != nil {
		return nil, err
	}
	if err := c.do(ctx, "GET", "/v1/payreq/"+url.PathEscape(bolt11), nil, &out, 15*time.Second); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendPaymentRequest is the body of POST /v2/router/send (SendPaymentV2).
type SendPaymentRequest struct {
	PaymentRequest string `json:"payment_request"`
	AmtMsat        Int64  `json:"amt_msat,omitempty"`
	FeeLimitMsat   Int64  `json:"fee_limit_msat"`
	TimeoutSeconds int32  `json:"timeout_seconds"`
	NoInflightUpd  bool   `json:"no_inflight_updates"`
}

// Payment is the subset of lnrpc.Payment streamed back by SendPaymentV2.
type Payment struct {
	PaymentHash     string `json:"payment_hash"`
	PaymentPreimage string `json:"payment_preimage"`
	ValueMsat       Int64  `json:"value_msat"`
	FeeMsat         Int64  `json:"fee_msat"`
	Status          string `json:"status"` // IN_FLIGHT, SUCCEEDED, FAILED, UNKNOWN, INITIATED
	FailureReason   string `json:"failure_reason"`
	CreationTimeNs  Int64  `json:"creation_time_ns"`
}

// UnresolvedError is returned by SendPaymentV2 when the outcome is unknown:
// the request went out and no terminal status came back (a timeout, a dropped
// connection, an error in the middle of the stream). The payment may well be
// in flight on the node. It must never be treated as a failure; only
// TrackPayment can say what happened.
type UnresolvedError struct{ Err error }

func (e *UnresolvedError) Error() string { return "payment outcome unknown: " + e.Err.Error() }
func (e *UnresolvedError) Unwrap() error { return e.Err }

// ErrPaymentNotFound is TrackPayment's answer for a hash LND never started
// paying.
var ErrPaymentNotFound = errors.New("lnd: payment not found")

// IsPaymentHash reports whether s is 32 bytes of lowercase hex.
func IsPaymentHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// NormalizeBolt11 strips a "lightning:" prefix, lowercases, and accepts only
// what a BOLT11 invoice can be made of: "ln" followed by bech32 characters.
func NormalizeBolt11(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 10 && strings.EqualFold(s[:10], "lightning:") {
		s = s[10:]
	}
	s = strings.ToLower(s)
	if len(s) < 12 || len(s) > 8192 || !strings.HasPrefix(s, "ln") {
		return "", errors.New("not a lightning invoice")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return "", errors.New("not a lightning invoice")
		}
	}
	return s, nil
}

// TrackPayment asks LND for the current state of a payment it initiated
// (TrackPaymentV2, first update only). ErrPaymentNotFound means LND never
// started one for this hash.
func (c *Client) TrackPayment(ctx context.Context, paymentHashHex string) (*Payment, error) {
	if !IsPaymentHash(paymentHashHex) {
		return nil, fmt.Errorf("payment hash must be 32 bytes hex")
	}
	raw, _ := hex.DecodeString(paymentHashHex)
	// grpc-gateway takes bytes fields in the path as base64.
	path := "/v2/router/track/" + url.PathEscape(base64.URLEncoding.EncodeToString(raw)) + "?no_inflight_updates=false"
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var out *Payment
	err := c.stream(ctx, path, func(msg json.RawMessage) error {
		var p Payment
		if err := json.Unmarshal(msg, &p); err != nil {
			return err
		}
		out = &p
		return errStopStream
	})
	if out != nil {
		return out, nil
	}
	var le *Error
	if errors.As(err, &le) && (le.Status == http.StatusNotFound || le.Code == 5) {
		return nil, ErrPaymentNotFound
	}
	if err == nil {
		err = errors.New("payment stream ended without an update")
	}
	return nil, err
}

var errStopStream = errors.New("stop")

// SendPaymentV2 pays an invoice and returns the terminal Payment. The stream
// carries the whole attempt; the macaroon used decides what LND and the
// guard's middleware allow.
//
// Three outcomes, and the difference matters for money: a terminal *Payment
// (SUCCEEDED or FAILED); an *Error, when LND answered the request with an
// error status before streaming anything; or an *UnresolvedError, when the
// answer never came.
func (c *Client) SendPaymentV2(ctx context.Context, req SendPaymentRequest) (*Payment, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v2/router/send", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if c.macaroon != "" {
		httpReq.Header.Set("Grpc-Metadata-macaroon", c.macaroon)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(httpReq)
	if err != nil {
		return nil, &UnresolvedError{Err: err}
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		e := &Error{Status: res.StatusCode}
		// A streaming endpoint wraps its error as {"error": {...}}.
		var env struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		} else {
			_ = json.Unmarshal(raw, e)
		}
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return nil, e
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env struct {
			Result *Payment `json:"result"`
			Error  *Error   `json:"error"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, &UnresolvedError{Err: fmt.Errorf("decode payment update: %w", err)}
		}
		if env.Error != nil {
			// An error in the middle of the stream says the stream ended,
			// not how the payment did.
			return nil, &UnresolvedError{Err: env.Error}
		}
		if env.Result != nil && (env.Result.Status == "SUCCEEDED" || env.Result.Status == "FAILED") {
			return env.Result, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, &UnresolvedError{Err: err}
	}
	return nil, &UnresolvedError{Err: errors.New("payment stream ended without a final status")}
}

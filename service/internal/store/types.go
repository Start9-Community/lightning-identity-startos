// Package store is core's durable state: identities, NWC connections and the
// invoice, payment and adjustment ledger, in a single bbolt file. Secret key material is encrypted at
// rest with a master key held beside the database (see Sealer); everything
// else is plain JSON values keyed as described on each bucket.
package store

import "time"

// Identity is one Lightning Address / NIP-05 name / NWC wallet service.
type Identity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`         // local part, lowercase
	DisplayName string `json:"display_name"` // free text shown in LNURL metadata
	Disabled    bool   `json:"disabled"`

	// NIP-05: the user's own Nostr pubkey (hex), distinct from the service keys.
	UserPubkey   string `json:"user_pubkey,omitempty"`
	NIP05Enabled bool   `json:"nip05_enabled"`

	// Per-identity service keys. The secret halves are sealed (see Sealer).
	ZapPubkey    string `json:"zap_pubkey"`
	ZapSecretEnc []byte `json:"zap_secret_enc"`
	NWCPubkey    string `json:"nwc_pubkey"`
	NWCSecretEnc []byte `json:"nwc_secret_enc"`

	// LNURL-pay bounds.
	MinSendableMsat int64 `json:"min_sendable_msat"`
	MaxSendableMsat int64 `json:"max_sendable_msat"`
	CommentAllowed  int   `json:"comment_allowed"`

	// Extra relays zap receipts are published to, besides the ones the zap
	// request names and the embedded relay (always included).
	Relays []string `json:"relays,omitempty"`

	// The relay this identity's NWC traffic runs on: what the connection
	// string names, where the info event goes, where requests are read and
	// answered. Empty means the embedded relay.
	NWCRelay string `json:"nwc_relay,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Connection is one NWC pairing of an identity. Connections are revoked, never
// deleted, so ledger rows keep their referent.
type Connection struct {
	ID           string     `json:"id"`
	IdentityID   string     `json:"identity_id"`
	Label        string     `json:"label"`
	ClientPubkey string     `json:"client_pubkey"`
	Methods      []string   `json:"methods"`
	Notify       bool       `json:"notifications"`
	BudgetMsat   int64      `json:"budget_msat,omitempty"`   // 0 = no budget
	BudgetPeriod string     `json:"budget_period,omitempty"` // daily, weekly, monthly, never
	MaxPayMsat   int64      `json:"max_payment_msat,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// Active reports whether a connection may be used right now.
func (c *Connection) Active(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
		return false
	}
	return true
}

// Allows reports whether the connection grants a NIP-47 method.
func (c *Connection) Allows(method string) bool {
	for _, m := range c.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// Invoice states.
const (
	InvoiceOpen     = "open"
	InvoiceSettled  = "settled"
	InvoiceExpired  = "expired"
	InvoiceCanceled = "canceled"
)

// Invoice sources.
const (
	SourceLNURL = "lnurl"
	SourceZap   = "zap"
	SourceNWC   = "nwc"
)

// Invoice is one receivable this service created, keyed by payment hash.
type Invoice struct {
	PaymentHash     string    `json:"payment_hash"`
	IdentityID      string    `json:"identity_id"`
	ConnectionID    string    `json:"connection_id,omitempty"`
	Source          string    `json:"source"`
	AmountMsat      int64     `json:"amount_msat"`
	Description     string    `json:"description,omitempty"`
	DescriptionHash string    `json:"description_hash,omitempty"`
	Bolt11          string    `json:"bolt11"`
	Comment         string    `json:"comment,omitempty"`
	PayerData       string    `json:"payer_data,omitempty"`
	ZapRequest      string    `json:"zap_request,omitempty"` // verbatim kind-9734 JSON
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	State           string    `json:"state"`
	SettledAt       time.Time `json:"settled_at,omitempty"`
	AmtPaidMsat     int64     `json:"amt_paid_msat,omitempty"`
	PreimageEnc     []byte    `json:"preimage_enc,omitempty"`
	ReceiptID       string    `json:"receipt_id,omitempty"`
	ReceiptAt       time.Time `json:"receipt_at,omitempty"`
	ReceiptRelays   []string  `json:"receipt_relays,omitempty"`
	ReceiptAttempts int       `json:"receipt_attempts,omitempty"`
	NotifiedAt      time.Time `json:"notified_at,omitempty"`
	// Metadata is what the app that asked for this invoice (NWC
	// make_invoice) attached to it: a JSON object, kept verbatim.
	Metadata string `json:"metadata,omitempty"`
}

// Settings are the operator's service-wide Lightning settings, edited in
// the Admin UI (no restart). See core.DefaultSettings for the defaults.
type Settings struct {
	RouteHints           bool  `json:"route_hints"`            // LND `private`: hints for unannounced channels
	SelfPay              bool  `json:"self_pay"`               // settle this node's own invoices internally
	InvoiceExpirySeconds int64 `json:"invoice_expiry_seconds"` // default expiry for LNURL/zap invoices
	// The most a payment may cost to route: FeeLimitPPM of the amount, but
	// never less than FeeLimitMinMsat. Both zero means "not set yet".
	FeeLimitPPM     int64     `json:"fee_limit_ppm"`
	FeeLimitMinMsat int64     `json:"fee_limit_min_msat"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Meta is small bookkeeping (LND subscription indices).
type Meta struct {
	LastAddIndex    int64 `json:"last_add_index"`
	LastSettleIndex int64 `json:"last_settle_index"`
}

// Payment states.
const (
	PaymentPending = "pending"
	PaymentSettled = "settled"
	PaymentFailed  = "failed"
)

// Payment is one outgoing payment made through a connection, keyed by
// payment hash. Pending rows hold budget until they resolve.
type Payment struct {
	PaymentHash   string    `json:"payment_hash"`
	IdentityID    string    `json:"identity_id"`
	ConnectionID  string    `json:"connection_id"`
	AmountMsat    int64     `json:"amount_msat"`
	FeeLimitMsat  int64     `json:"fee_limit_msat"`
	FeeMsat       int64     `json:"fee_msat"`
	Bolt11        string    `json:"bolt11"`
	Description   string    `json:"description,omitempty"`
	Destination   string    `json:"destination,omitempty"`
	State         string    `json:"state"`
	FailureReason string    `json:"failure_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	SettledAt     time.Time `json:"settled_at,omitempty"`
	PreimageEnc   []byte    `json:"preimage_enc,omitempty"`
	NotifiedAt    time.Time `json:"notified_at,omitempty"`
	// Internal marks a self-payment: the invoice was this node's own and was
	// settled in the ledger without a Lightning payment (no fee, no route).
	Internal bool `json:"internal,omitempty"`
	// Metadata is what the paying app said the payment was for: the JSON
	// object from pay_invoice's `metadata` (for a zap, {"nostr": <the
	// kind-9734 request>}), kept verbatim and handed back in
	// list_transactions. An invoice says how much and to which node, never
	// to whom; this is the only place a wallet's history can learn it.
	Metadata string `json:"metadata,omitempty"`
}

// Adjustment is an operator credit or debit on an identity's balance. It moves
// no sats on the node; it is bookkeeping, the way an LNbits admin tops up a
// wallet. Adjustments never appear in NIP-47 transaction lists.
type Adjustment struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"identity_id"`
	AmountMsat int64     `json:"amount_msat"` // positive = credit, negative = debit
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Balance is an identity's ledger position in msat.
type Balance struct {
	Received  int64 `json:"received_msat"`  // settled incoming
	Sent      int64 `json:"sent_msat"`      // settled outgoing, amount + fee
	InFlight  int64 `json:"in_flight_msat"` // pending outgoing, amount + fee limit
	Adjusted  int64 `json:"adjusted_msat"`  // net operator adjustments
	Available int64 `json:"available_msat"` // Received + Adjusted − Sent − InFlight
}

// Budget periods a connection may use.
const (
	PeriodDaily   = "daily"
	PeriodWeekly  = "weekly"
	PeriodMonthly = "monthly"
	PeriodYearly  = "yearly"
	PeriodNever   = "never" // the budget is a lifetime total
)

// PeriodStart returns when the current budget period began, or the zero time
// for a lifetime budget.
func PeriodStart(period string, now time.Time) time.Time {
	switch period {
	case PeriodDaily:
		return now.Add(-24 * time.Hour)
	case PeriodWeekly:
		return now.Add(-7 * 24 * time.Hour)
	case PeriodMonthly:
		return now.AddDate(0, -1, 0)
	case PeriodYearly:
		return now.AddDate(-1, 0, 0)
	default:
		return time.Time{}
	}
}

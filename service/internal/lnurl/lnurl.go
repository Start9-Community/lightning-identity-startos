// Package lnurl builds and validates LUD-06 / LUD-16 (Lightning Address)
// documents, with the LUD-12 comment, LUD-18 payer data, LUD-21 verify and
// NIP-57 extensions this service supports.
package lnurl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lundog/lightning-identity-startos/service/internal/identity"
)

// Limits every identity is clamped to, whatever the operator typed.
const (
	AbsoluteMinMsat   = 1_000
	AbsoluteMaxMsat   = 10_000_000_000 // 0.1 BTC per invoice
	MaxCommentAllowed = 1_024
	MaxPayerData      = 1_024
	MaxZapRequest     = 4_096
)

// PayResponse is the LUD-06 pay request document.
type PayResponse struct {
	Tag            string         `json:"tag"`
	Callback       string         `json:"callback"`
	MinSendable    int64          `json:"minSendable"`
	MaxSendable    int64          `json:"maxSendable"`
	Metadata       string         `json:"metadata"`
	CommentAllowed int            `json:"commentAllowed,omitempty"`
	AllowsNostr    bool           `json:"allowsNostr,omitempty"`
	NostrPubkey    string         `json:"nostrPubkey,omitempty"`
	PayerData      *PayerDataSpec `json:"payerData,omitempty"`
}

// PayerDataSpec is LUD-18's optional fields block.
type PayerDataSpec struct {
	Name  *PayerField `json:"name,omitempty"`
	Email *PayerField `json:"email,omitempty"`
}

// PayerField marks a LUD-18 field as optional/mandatory.
type PayerField struct {
	Mandatory bool `json:"mandatory"`
}

// Metadata renders the LUD-06 metadata array for an address: the string is
// what both ends hash, so it is built in exactly one place.
func Metadata(address, displayName string) string {
	text := "Pay to " + address
	if strings.TrimSpace(displayName) != "" {
		text = "Pay " + strings.TrimSpace(displayName) + " (" + address + ")"
	}
	raw, _ := json.Marshal([][]string{{"text/plain", text}, {"text/identifier", address}})
	return string(raw)
}

// MetadataHash is sha256 over the metadata string, as LUD-06 prescribes.
func MetadataHash(metadata string) []byte {
	h := sha256.Sum256([]byte(metadata))
	return h[:]
}

// BuildPayResponse assembles the document for an identity on a domain.
func BuildPayResponse(doc *identity.Doc, e *identity.Entry) PayResponse {
	min, max := ClampBounds(e.MinMsat, e.MaxMsat)
	addr := doc.Address(e)
	res := PayResponse{
		Tag:         "payRequest",
		Callback:    strings.TrimRight(doc.BaseURL, "/") + "/lnurlp/" + e.Name + "/callback",
		MinSendable: min,
		MaxSendable: max,
		Metadata:    Metadata(addr, e.DisplayName),
		PayerData:   &PayerDataSpec{Name: &PayerField{}, Email: &PayerField{}},
	}
	if e.CommentAllowed > 0 {
		res.CommentAllowed = clampInt(e.CommentAllowed, 1, MaxCommentAllowed)
	}
	if e.ZapPubkey != "" {
		res.AllowsNostr = true
		res.NostrPubkey = e.ZapPubkey
	}
	return res
}

// ClampBounds applies the absolute limits and fixes an inverted range.
func ClampBounds(min, max int64) (int64, int64) {
	if min < AbsoluteMinMsat {
		min = AbsoluteMinMsat
	}
	if max <= 0 || max > AbsoluteMaxMsat {
		max = AbsoluteMaxMsat
	}
	if max < min {
		max = min
	}
	return min, max
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// CallbackResponse is the LUD-06 invoice answer.
type CallbackResponse struct {
	PR     string   `json:"pr"`
	Routes []string `json:"routes"`
	Verify string   `json:"verify,omitempty"`
}

// VerifyResponse is the LUD-21 answer.
type VerifyResponse struct {
	Status   string  `json:"status"`
	Settled  bool    `json:"settled"`
	Preimage *string `json:"preimage"`
	PR       string  `json:"pr"`
}

// CallbackRequest is what edge validated and forwards to core.
type CallbackRequest struct {
	Identity   string `json:"identity"`
	AmountMsat int64  `json:"amount_msat"`
	Comment    string `json:"comment,omitempty"`
	PayerData  string `json:"payer_data,omitempty"`
	ZapRequest string `json:"zap_request,omitempty"`
}

// ValidateAmount checks an amount against configured bounds.
func ValidateAmount(minMsat, maxMsat, amount int64) error {
	min, max := ClampBounds(minMsat, maxMsat)
	if amount < min || amount > max {
		return fmt.Errorf("amount must be between %d and %d msat", min, max)
	}
	return nil
}

// ValidateComment enforces LUD-12's length rule.
func ValidateComment(commentAllowed int, comment string) error {
	if comment == "" {
		return nil
	}
	if commentAllowed <= 0 {
		return fmt.Errorf("comments are not accepted for this address")
	}
	if len([]rune(comment)) > clampInt(commentAllowed, 1, MaxCommentAllowed) {
		return fmt.Errorf("comment longer than %d characters", commentAllowed)
	}
	return nil
}

// ValidatePayerData bounds and parses LUD-18 payer data without storing
// anything but the compact JSON.
func ValidatePayerData(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > MaxPayerData {
		return "", fmt.Errorf("payer data too large")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", fmt.Errorf("payer data is not a JSON object")
	}
	out, _ := json.Marshal(v)
	return string(out), nil
}

// HexHash renders a description hash for logs and JSON.
func HexHash(b []byte) string { return hex.EncodeToString(b) }

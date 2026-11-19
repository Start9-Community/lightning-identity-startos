// Package zap implements the NIP-57 pieces: validating a zap request handed
// to the LNURL callback and building the zap receipt once the invoice settles.
package zap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Kinds from NIP-57.
const (
	KindZapRequest = 9734
	KindZapReceipt = 9735
)

// Request is a validated kind-9734 event plus the fields the receipt needs.
type Request struct {
	Event     *nostr.Event
	Raw       string // verbatim JSON as the sender signed it (hashed into the invoice)
	Recipient string // the single p tag
	EventID   string // the optional e tag
	Coord     string // the optional a tag
	Relays    []string
}

// Validate applies NIP-57 Appendix D to the raw zap request JSON. amount is
// the callback's amount in msat.
func Validate(raw string, amount int64) (*Request, error) {
	var ev nostr.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, fmt.Errorf("zap request is not a nostr event")
	}
	if ev.Kind != KindZapRequest {
		return nil, fmt.Errorf("zap request must be kind %d", KindZapRequest)
	}
	if ok, err := ev.CheckSignature(); err != nil || !ok {
		return nil, fmt.Errorf("zap request signature is invalid")
	}
	req := &Request{Event: &ev, Raw: raw}
	var pCount, eCount, bigPCount int
	for _, t := range ev.Tags {
		if len(t) < 1 {
			continue
		}
		switch t[0] {
		case "p":
			pCount++
			if len(t) < 2 || !isHex(t[1], 64) {
				return nil, fmt.Errorf("zap request p tag is not a pubkey")
			}
			req.Recipient = t[1]
		case "e":
			eCount++
			if len(t) < 2 || !isHex(t[1], 64) {
				return nil, fmt.Errorf("zap request e tag is not an event id")
			}
			req.EventID = t[1]
		case "a":
			if len(t) >= 2 {
				req.Coord = t[1]
			}
		case "P":
			bigPCount++
		case "relays":
			for _, r := range t[1:] {
				r = strings.TrimSpace(r)
				if strings.HasPrefix(r, "wss://") || strings.HasPrefix(r, "ws://") {
					req.Relays = append(req.Relays, r)
				}
			}
		case "amount":
			if len(t) < 2 {
				return nil, fmt.Errorf("zap request amount tag is empty")
			}
			v, err := strconv.ParseInt(t[1], 10, 64)
			if err != nil || v != amount {
				return nil, fmt.Errorf("zap request amount does not match the requested amount")
			}
		}
	}
	if pCount != 1 {
		return nil, fmt.Errorf("zap request must have exactly one p tag")
	}
	if eCount > 1 {
		return nil, fmt.Errorf("zap request must have at most one e tag")
	}
	if bigPCount > 1 {
		return nil, fmt.Errorf("zap request must have at most one P tag")
	}
	if len(req.Relays) == 0 {
		return nil, fmt.Errorf("zap request has no relays tag")
	}
	return req, nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Receipt builds the kind-9735 event for a settled zap and signs it with the
// identity's zap key (hex secret).
func Receipt(req *Request, bolt11, preimageHex string, settledAt time.Time, zapSecretHex string) (*nostr.Event, error) {
	ev := &nostr.Event{
		Kind:      KindZapReceipt,
		CreatedAt: nostr.Timestamp(settledAt.Unix()),
		Content:   "",
		Tags: nostr.Tags{
			{"p", req.Recipient},
			{"P", req.Event.PubKey},
			{"bolt11", bolt11},
			{"description", req.Raw},
		},
	}
	if req.EventID != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"e", req.EventID})
	}
	if req.Coord != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"a", req.Coord})
	}
	if preimageHex != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"preimage", preimageHex})
	}
	if err := ev.Sign(zapSecretHex); err != nil {
		return nil, err
	}
	return ev, nil
}

// Package macaroon adds LND first-party caveats to a baked macaroon. LND's
// BakeMacaroon RPC only sets permissions; the constraints a credential carries
// (expiry, IP range, custom caveats) are appended by the holder and verified by
// LND on every request.
package macaroon

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	mac "gopkg.in/macaroon.v2"
)

// Caveat condition names, as LND's macaroons/constraints.go spells them.
const (
	TimeBefore = "time-before"
	IPAddr     = "ipaddr"
	IPRange    = "iprange"
	LNDCustom  = "lnd-custom"
)

// TimeBeforeCaveat expires the credential at t (RFC 3339, as LND expects).
func TimeBeforeCaveat(t time.Time) string {
	return TimeBefore + " " + t.UTC().Format(time.RFC3339)
}

// IPRangeCaveat locks the credential to connections LND sees from cidr.
func IPRangeCaveat(cidr *net.IPNet) string {
	return IPRange + " " + cidr.String()
}

// CustomCaveat builds `lnd-custom <name> <condition>`: LND routes requests
// carrying it to the RPC middleware registered under name and rejects them
// outright while no such middleware is connected.
func CustomCaveat(name, condition string) string {
	return LNDCustom + " " + name + " " + condition
}

// AddCaveats decodes a hex macaroon, appends the caveats in order and returns
// the result as hex.
func AddCaveats(macaroonHex string, caveats ...string) (string, error) {
	raw, err := hex.DecodeString(macaroonHex)
	if err != nil {
		return "", fmt.Errorf("macaroon is not hex: %w", err)
	}
	var m mac.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return "", fmt.Errorf("decode macaroon: %w", err)
	}
	for _, c := range caveats {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if err := m.AddFirstPartyCaveat([]byte(c)); err != nil {
			return "", fmt.Errorf("add caveat %q: %w", c, err)
		}
	}
	out, err := m.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(out), nil
}

// Caveats lists the first-party caveat conditions a hex macaroon carries, in
// order, so the guard can report exactly what it baked.
func Caveats(macaroonHex string) ([]string, error) {
	raw, err := hex.DecodeString(macaroonHex)
	if err != nil {
		return nil, err
	}
	var m mac.Macaroon
	if err := m.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	var out []string
	for _, c := range m.Caveats() {
		if len(c.VerificationId) == 0 { // first-party
			out = append(out, string(c.Id))
		}
	}
	return out, nil
}

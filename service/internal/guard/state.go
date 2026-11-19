package guard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// State is the guard's persisted policy: the latch, the two caps, the custom
// caveat nonce and the spend ledger that backs the rolling window. It lives in
// the guard-only directory, so nothing reachable from the network can write
// it; only the guard (lowering) and the StartOS action (raising, enabling)
// change it.
type State struct {
	SendingEnabled bool   `json:"sending_enabled"`
	MaxPaymentMsat int64  `json:"max_payment_msat"`
	Max24hMsat     int64  `json:"max_24h_msat"`
	Nonce          string `json:"nonce"` // condition of the lnd-custom caveat
	// Committed spends (amount + fee) inside the rolling window.
	Ledger []LedgerEntry `json:"ledger"`
	// Payments the guard let through and has not seen resolve. They count
	// against the window exactly like committed spends, and are persisted so
	// a guard restart cannot forget money that is still in flight.
	Reservations []SavedReservation `json:"reservations,omitempty"`
	// Ids of authorizations already consumed, so a replayed file is inert.
	Applied   []string  `json:"applied_authorizations"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SavedReservation is one unresolved payment as written to disk.
type SavedReservation struct {
	At   time.Time `json:"at"`
	Msat int64     `json:"msat"`
	Hash string    `json:"hash"`
}

// LedgerEntry is one committed spend.
type LedgerEntry struct {
	At   time.Time `json:"at"`
	Msat int64     `json:"msat"`
	Hash string    `json:"payment_hash,omitempty"`
}

// Authorization is what the StartOS action writes into the guard directory.
// Its authority comes from where it sits — a directory only the guard and the
// package runtime can reach — not from a signature.
type Authorization struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Enabled        bool      `json:"enabled"`
	MaxPaymentMsat int64     `json:"max_payment_msat"`
	Max24hMsat     int64     `json:"max_24h_msat"`
}

const (
	stateFile         = "state.json"
	authorizationFile = "authorization.json"
	window            = 24 * time.Hour
)

func (g *Guard) statePath() string { return filepath.Join(g.cfg.StateDir, stateFile) }
func (g *Guard) authPath() string  { return filepath.Join(g.cfg.StateDir, authorizationFile) }

func (g *Guard) loadState() error {
	raw, err := os.ReadFile(g.statePath())
	if errors.Is(err, os.ErrNotExist) {
		g.state = State{}
		return nil
	}
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("guard state is corrupt: %w", err)
	}
	g.state = st
	// Reservations from before the restart come back under ids no live
	// request can have; nothing will ever resolve them by id, so they age
	// into the ledger as spent unless a lookup on LND says otherwise.
	for i, r := range st.Reservations {
		if r.Msat > 0 {
			g.reservations[restoredIDBase+uint64(i)] = &reservation{msat: r.Msat, at: r.At, hash: r.Hash, unsure: true}
		}
	}
	return nil
}

// restoredIDBase keeps reloaded reservations clear of LND's request ids.
const restoredIDBase = uint64(1) << 62

// saveState persists under the state lock (callers hold it).
func (g *Guard) saveStateLocked() error {
	g.state.UpdatedAt = time.Now().UTC()
	g.pruneLedgerLocked(time.Now())
	g.state.Reservations = g.state.Reservations[:0]
	for _, r := range g.reservations {
		g.state.Reservations = append(g.state.Reservations, SavedReservation{At: r.at, Msat: r.msat, Hash: r.hash})
	}
	sort.Slice(g.state.Reservations, func(i, j int) bool { return g.state.Reservations[i].At.Before(g.state.Reservations[j].At) })
	raw, err := json.MarshalIndent(g.state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(g.statePath(), raw, 0o600)
}

func (g *Guard) pruneLedgerLocked(now time.Time) {
	kept := g.state.Ledger[:0]
	for _, e := range g.state.Ledger {
		if now.Sub(e.At) < window {
			kept = append(kept, e)
		}
	}
	g.state.Ledger = kept
}

// spentLocked is the committed total inside the window.
func (g *Guard) spentLocked(now time.Time) int64 {
	var sum int64
	for _, e := range g.state.Ledger {
		if now.Sub(e.At) < window {
			sum += e.Msat
		}
	}
	return sum
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// applyAuthorization consumes guard/authorization.json if it is fresh and
// unseen: it is the only path that enables sending or raises a cap.
func (g *Guard) applyAuthorization() {
	raw, err := os.ReadFile(g.authPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		g.fail(fmt.Errorf("read authorization: %w", err))
		return
	}
	var a Authorization
	if err := json.Unmarshal(raw, &a); err != nil {
		g.fail(fmt.Errorf("authorization is not valid JSON; ignoring it: %w", err))
		_ = os.Remove(g.authPath())
		return
	}
	now := time.Now()
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	for _, id := range g.state.Applied {
		if id == a.ID {
			_ = os.Remove(g.authPath())
			return
		}
	}
	if a.ID == "" || now.After(a.ExpiresAt) {
		g.log.Warn("guard: authorization ignored", "id", a.ID, "expired", now.After(a.ExpiresAt))
		_ = os.Remove(g.authPath())
		return
	}
	if a.MaxPaymentMsat < 0 || a.Max24hMsat < 0 || a.MaxPaymentMsat > a.Max24hMsat {
		g.log.Warn("guard: authorization refused: per-payment cap must be ≤ 24h cap and both ≥ 0", "id", a.ID)
		_ = os.Remove(g.authPath())
		return
	}
	wasEnabled := g.state.SendingEnabled
	g.state.SendingEnabled = a.Enabled
	g.state.MaxPaymentMsat = a.MaxPaymentMsat
	g.state.Max24hMsat = a.Max24hMsat
	if a.Enabled && (!wasEnabled || g.state.Nonce == "") {
		// A fresh nonce on every enable: a spend credential from an earlier
		// enabled period no longer matches and fails closed.
		g.state.Nonce = newNonce()
	}
	g.state.Applied = append(g.state.Applied, a.ID)
	if len(g.state.Applied) > 64 {
		g.state.Applied = g.state.Applied[len(g.state.Applied)-64:]
	}
	if err := g.saveStateLocked(); err != nil {
		g.fail(err)
		return
	}
	_ = os.Remove(g.authPath())
	g.log.Info("guard: authorization applied", "id", a.ID, "enabled", a.Enabled, "max_payment_msat", a.MaxPaymentMsat, "max_24h_msat", a.Max24hMsat)
	if !a.Enabled {
		g.dropSpendCredential()
	}
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// LowerCaps is the socket path for tightening: each cap may only go down.
func (g *Guard) LowerCaps(maxPayment, max24h int64) error {
	g.stateMu.Lock()
	defer g.stateMu.Unlock()
	if maxPayment < 0 || max24h < 0 {
		return errors.New("caps must be ≥ 0")
	}
	if maxPayment > g.state.MaxPaymentMsat || max24h > g.state.Max24hMsat {
		return errors.New("caps can only be lowered here; raise them with the Authorize Sending action in StartOS")
	}
	if maxPayment > max24h {
		return errors.New("per-payment cap must be ≤ the 24-hour cap")
	}
	g.state.MaxPaymentMsat, g.state.Max24hMsat = maxPayment, max24h
	return g.saveStateLocked()
}

// DisableSending flips the latch off and removes the spend credential. It is
// the free direction: anyone who can reach the guard socket may do it.
func (g *Guard) DisableSending() error {
	g.stateMu.Lock()
	g.state.SendingEnabled = false
	err := g.saveStateLocked()
	g.stateMu.Unlock()
	g.dropSpendCredential()
	return err
}

func (g *Guard) dropSpendCredential() {
	_ = os.Remove(g.spendPath())
	g.update(func(s *Status) {
		s.SpendExpires = time.Time{}
		s.SpendCaveats = nil
		s.SendingEnabled = false
	})
}

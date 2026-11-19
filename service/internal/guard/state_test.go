package guard

import (
	"path/filepath"
	"testing"
	"time"
)

// A payment the guard let through and has not seen resolve must survive a
// guard restart: forgetting it would free that much of the 24-hour window
// while the money is still in flight.
func TestReservationsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{CredentialsDir: filepath.Join(dir, "credentials"), StateDir: filepath.Join(dir, "guard"), SocketPath: filepath.Join(dir, "g.sock")}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.stateMu.Lock()
	g.state.SendingEnabled, g.state.MaxPaymentMsat, g.state.Max24hMsat = true, 60_000, 120_000
	g.reservations[7] = &reservation{msat: 40_000, at: time.Now().Add(-time.Minute), hash: "aa"}
	g.reservations[9] = &reservation{msat: 15_000, at: time.Now(), hash: "bb"}
	if err := g.saveStateLocked(); err != nil {
		t.Fatal(err)
	}
	g.stateMu.Unlock()

	g2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g2.stateMu.Lock()
	defer g2.stateMu.Unlock()
	if got := g2.reservedLocked(); got != 55_000 {
		t.Fatalf("reserved after restart = %d, want 55000", got)
	}
	for id, r := range g2.reservations {
		if id < restoredIDBase || !r.unsure {
			t.Fatalf("restored reservation %d: id must be out of LND's range and marked unsure: %+v", id, r)
		}
	}
	// Left alone past the TTL, they are committed as spent, never dropped.
	g2.expireReservationsLocked(time.Now().Add(reservationTTL + time.Minute))
	if got := g2.reservedLocked(); got != 0 {
		t.Fatalf("reserved after expiry = %d", got)
	}
	if got := g2.spentLocked(time.Now()); got != 55_000 {
		t.Fatalf("spent after expiry = %d, want 55000", got)
	}
}

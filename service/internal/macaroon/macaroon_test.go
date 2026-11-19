package macaroon

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	mac "gopkg.in/macaroon.v2"
)

func TestAddCaveats(t *testing.T) {
	m, err := mac.New([]byte("rootkey"), []byte("id"), "lnd", mac.V2)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := m.MarshalBinary()
	_, cidr, _ := net.ParseCIDR("10.0.3.0/24")
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	out, err := AddCaveats(hex.EncodeToString(raw), TimeBeforeCaveat(exp), IPRangeCaveat(cidr), CustomCaveat("guard", "nonce"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := Caveats(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"time-before 2030-01-02T03:04:05Z", "iprange 10.0.3.0/24", "lnd-custom guard nonce"}
	if len(cs) != 3 {
		t.Fatalf("got %v", cs)
	}
	for i := range want {
		if cs[i] != want[i] {
			t.Errorf("caveat %d: got %q want %q", i, cs[i], want[i])
		}
	}
}

package httpx

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":              true,
		"2606:4700:4700::1111": true,
		"127.0.0.1":            false,
		"127.8.9.10":           false,
		"10.0.3.1":             false, // the StartOS bridge
		"172.18.0.2":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"100.100.100.100":      false, // CGNAT / Tailscale
		"0.0.0.0":              false,
		"255.255.255.255":      false,
		"::1":                  false,
		"::":                   false,
		"::ffff:127.0.0.1":     false, // IPv4-mapped loopback
		"::ffff:10.0.3.1":      false,
		"64:ff9b::7f00:1":      false, // NAT64 of 127.0.0.1
		"2002:7f00:1::":        false, // 6to4 of 127.0.0.1
		"fd00::1":              false,
		"fe80::1":              false,
		"ff02::1":              false,
	} {
		if got := IsPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsPublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
	if IsPublicAddr(netip.Addr{}) {
		t.Error("the zero address is not public")
	}
}

func TestRateKey(t *testing.T) {
	for in, want := range map[string]string{
		"45.148.10.201":        "45.148.10.201",
		"::ffff:45.148.10.201": "45.148.10.201",
		"2001:db8:1:2::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"not an address":       "not an address",
	} {
		if got := RateKey(in); got != want {
			t.Errorf("RateKey(%q) = %q, want %q", in, got, want)
		}
	}
}

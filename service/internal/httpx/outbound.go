package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrNotPublic is returned when an outbound connection is refused because
// its destination is not a public address.
var ErrNotPublic = errors.New("destination is not a public address")

var trustedDial atomic.Value // func(hostport string) bool

// RestrictOutbound makes the default HTTP transport — which every Nostr
// relay connection goes through — refuse to connect to anything but public
// addresses, unless trusted(hostport) says the operator configured that
// destination.
//
// Relay URLs reach this service from strangers: a zap request names the
// relays its receipt should go to. Without this, a stranger could aim the
// service at loopback, at the StartOS bridge, or at the operator's LAN.
// The check is made on the address actually being connected to, after DNS
// resolution and on every redirect, so a hostname that resolves inward (or
// changes its mind between lookups) is refused like a literal address.
//
// LND and the guard are reached through their own pinned transports and
// unix sockets and are not affected.
func RestrictOutbound(trusted func(hostport string) bool) error {
	trustedDial.Store(trusted)
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("default transport is not an *http.Transport")
	}
	open := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	guarded := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: publicOnly}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if fn, _ := trustedDial.Load().(func(string) bool); fn != nil && fn(addr) {
			return open.DialContext(ctx, network, addr)
		}
		return guarded.DialContext(ctx, network, addr)
	}
	// A proxy from the environment would be dialled instead of the
	// destination and the check would see only the proxy.
	t.Proxy = nil
	return nil
}

// publicOnly runs on the resolved address just before connect(2).
func publicOnly(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotPublic, address)
	}
	if !IsPublicAddr(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNotPublic, ap.Addr())
	}
	return nil
}

var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8",       // "this network"
		"10.0.0.0/8",      // private
		"100.64.0.0/10",   // carrier-grade NAT (also Tailscale)
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local (cloud metadata lives here)
		"172.16.0.0/12",   // private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"192.168.0.0/16",  // private
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"224.0.0.0/3",     // multicast, reserved, broadcast
		"::/127",          // unspecified, loopback
		"64:ff9b::/96",    // NAT64: embeds an IPv4 address
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4: embeds an IPv4 address
		"fc00::/7",        // unique local
		"fe80::/10",       // link-local
		"ff00::/8",        // multicast
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// IsPublicAddr reports whether a is an address on the public internet.
func IsPublicAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap() // ::ffff:127.0.0.1 is 127.0.0.1
	if a.Zone() != "" {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

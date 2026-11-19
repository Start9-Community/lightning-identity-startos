package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// JSON writes v with the given status and no-store caching.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// LNURLError writes the LUD-06 error shape.
func LNURLError(w http.ResponseWriter, status int, reason string) {
	JSON(w, status, map[string]string{"status": "ERROR", "reason": reason})
}

// ClientIP returns the client address: the rightmost X-Forwarded-For entry,
// which is the one the StartOS reverse proxy appended, and otherwise the TCP
// peer. Only the rightmost value is trusted; anything a client wrote itself is
// to its left.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateKey is what a per-client limit is keyed on: an IPv4 address as it is,
// an IPv6 address by its /64. One IPv6 subscriber is handed a whole /64 and
// can send each request from a different address in it, so limiting single
// addresses limits nothing.
func RateKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// Limiter is a keyed token bucket: Allow(key) spends one token from key's
// bucket, which refills at rate per second up to burst. Idle buckets are
// evicted so the map stays bounded.
type Limiter struct {
	rate  float64
	burst float64
	mu    sync.Mutex
	b     map[string]*bucket
	last  time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// NewLimiter builds a limiter allowing `perMinute` sustained with `burst` slack.
func NewLimiter(perMinute, burst int) *Limiter {
	if perMinute <= 0 {
		perMinute = 60
	}
	if burst <= 0 {
		burst = perMinute
	}
	return &Limiter{rate: float64(perMinute) / 60, burst: float64(burst), b: map[string]*bucket{}, last: time.Now()}
}

// Allow reports whether key may proceed now.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.last) > time.Minute {
		for k, b := range l.b {
			if now.Sub(b.at) > 5*time.Minute {
				delete(l.b, k)
			}
		}
		l.last = now
	}
	b := l.b[key]
	if b == nil {
		b = &bucket{tokens: l.burst, at: now}
		l.b[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

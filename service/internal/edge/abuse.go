package edge

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
)

// Scanner blocking.
//
// A vulnerability scanner asks for hundreds of paths that do not exist
// (/.env, /.git/config, /vendor/...) in a few seconds. Nothing here answers
// them, but each one is a request served and a log line written, and the
// general rate limit has to stay loose enough for real clients that it lets
// most of a scan through. What sets a scanner apart is not its speed but
// that nearly every answer it gets is "not found": a wallet or a browser
// almost never causes one.
//
// So misses are counted per client. An address that collects more than
// MissesPerMinute of them is refused outright for BlockFor, and that is
// logged once rather than once per request.
const (
	MissesPerMinute = 20
	BlockFor        = 10 * time.Minute
	maxBlocked      = 50_000 // addresses remembered; beyond this the soonest to expire are dropped
)

type blockEntry struct {
	until   time.Time
	refused int
}

type missGuard struct {
	misses *httpx.Limiter
	now    func() time.Time

	mu      sync.Mutex
	blocked map[string]*blockEntry
}

func newMissGuard() *missGuard {
	return &missGuard{misses: httpx.NewLimiter(MissesPerMinute, MissesPerMinute), now: time.Now, blocked: map[string]*blockEntry{}}
}

// refuse reports whether key is blocked right now, and for how much longer.
// When a block has just run out it is removed and its tally returned, so the
// caller can log what it held back.
func (g *missGuard) refuse(key string) (blocked bool, left time.Duration, lifted *blockEntry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.blocked[key]
	if e == nil {
		return false, 0, nil
	}
	if now := g.now(); now.Before(e.until) {
		e.refused++
		return true, e.until.Sub(now), nil
	}
	delete(g.blocked, key)
	return false, 0, e
}

// miss records one not-found answer for key and reports whether that one
// tipped it into a block.
func (g *missGuard) miss(key string) bool {
	if g.misses.Allow(key) {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if len(g.blocked) >= maxBlocked {
		for k, e := range g.blocked {
			if !now.Before(e.until) {
				delete(g.blocked, k)
			}
		}
		for k := range g.blocked { // still full: make room, any entry will do
			if len(g.blocked) < maxBlocked {
				break
			}
			delete(g.blocked, k)
		}
	}
	if _, already := g.blocked[key]; already {
		return false
	}
	g.blocked[key] = &blockEntry{until: now.Add(BlockFor)}
	return true
}

// isMiss is what counts against a client: asking for something that is not
// here, or in a way nothing here accepts.
func isMiss(status int) bool {
	return status == http.StatusNotFound || status == http.StatusMethodNotAllowed
}

// fromThisHost reports whether a request was made from inside the
// container: core talking to the embedded relay over loopback. Such a
// request has no X-Forwarded-For, which the OS proxy adds to everything
// that comes from outside, so an outside client cannot pass for one.
func fromThisHost(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// blockable reports whether an address may be blocked at all. Only public
// ones: if the client address ever turns out to be a private one (a proxy
// in front that does not pass the real address on, an overlay network),
// then every visitor shares it, and blocking it would take the whole public
// interface down for ten minutes on the strength of one scanner.
func blockable(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && httpx.IsPublicAddr(a)
}

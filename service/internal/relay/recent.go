package relay

import (
	"context"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// How long, and how many, wallet requests and replies are kept for late
// subscribers.
const (
	RecentTTL      = 60 * time.Second
	RecentMax      = 2048
	RecentMaxBytes = 32 << 20 // of event content: replies can be MaxServiceEventBytes each
)

// recentReplies keeps NWC requests and responses in memory for a short
// while.
//
// Both kinds (23194, 23195) are ephemeral: the relay hands them to whoever
// is subscribed and forgets them. That assumes the other side is already
// listening, and twice it is not:
//
//   - Damus's wallet screen publishes its request and only then opens a
//     subscription for the reply. This service answers in a few
//     milliseconds, so the reply went out to nobody and the app showed a
//     blank wallet.
//   - Core's own subscription restarts for a moment whenever identities or
//     connections change. A request arriving in that moment was dropped.
//
// Keeping both for a minute, and serving them to a subscription that asks,
// makes the order irrelevant in both directions. General relays do the same
// (strfry keeps ephemeral events for five minutes). Core ignores a request
// it has already handled, and one whose NIP-40 expiration has passed.
//
// Nothing is written to disk, and notifications are not kept. What a late
// subscriber can read is exactly what it could have read by subscribing a
// moment earlier: an encrypted message.
type recentReplies struct {
	mu     sync.Mutex
	events []*nostr.Event // oldest first
	bytes  int            // content bytes held in events
	now    func() time.Time
}

func keptKind(k int) bool { return k == KindNWCRequest || k == KindNWCResponse }

func newRecentReplies() *recentReplies { return &recentReplies{now: time.Now} }

// add is khatru's OnEphemeralEvent hook.
func (r *recentReplies) add(_ context.Context, ev *nostr.Event) {
	if !keptKind(ev.Kind) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	for len(r.events) > 0 && (len(r.events) >= RecentMax || r.bytes+len(ev.Content) > RecentMaxBytes) {
		r.bytes -= len(r.events[0].Content)
		r.events = r.events[1:]
	}
	r.events = append(r.events, ev)
	r.bytes += len(ev.Content)
}

// pruneLocked drops replies older than RecentTTL, judged by their own
// timestamp (already held to a sane window by the relay's policies).
func (r *recentReplies) pruneLocked() {
	cutoff := nostr.Timestamp(r.now().Add(-RecentTTL).Unix())
	i := 0
	for i < len(r.events) && r.events[i].CreatedAt < cutoff {
		r.bytes -= len(r.events[i].Content)
		i++
	}
	r.events = r.events[i:]
}

// query is a khatru QueryEvents hook: the kept replies a filter matches.
//
// It always returns a channel, closed when done. khatru's REQ path tolerates
// a nil channel, but its expiration scan ranges over whatever comes back
// while holding a lock, and a nil channel there blocks the relay for good.
// Only a filter that names a kept kind is served, so that internal scans
// (which use an empty filter) never see what is kept here.
func (r *recentReplies) query(_ context.Context, f nostr.Filter) (chan *nostr.Event, error) {
	var out []*nostr.Event
	for _, k := range f.Kinds {
		if !keptKind(k) {
			continue
		}
		r.mu.Lock()
		r.pruneLocked()
		for _, ev := range r.events {
			if f.Matches(ev) {
				out = append(out, ev)
			}
		}
		r.mu.Unlock()
		break
	}
	ch := make(chan *nostr.Event, len(out))
	for _, ev := range out {
		ch <- ev
	}
	close(ch)
	return ch, nil
}

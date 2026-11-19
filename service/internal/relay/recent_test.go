package relay

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestRecentRepliesServeLateSubscribers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := newRecentReplies()
	r.now = func() time.Time { return now }
	ctx := context.Background()
	mk := func(kind int, reqID string, at time.Time) *nostr.Event {
		return &nostr.Event{ID: reqID + "-reply", Kind: kind, PubKey: "svc", CreatedAt: nostr.Timestamp(at.Unix()), Tags: nostr.Tags{{"e", reqID}, {"p", "client"}}}
	}
	r.add(ctx, mk(KindNWCResponse, "req1", now))
	r.add(ctx, mk(KindNWCNotify, "req2", now)) // notifications are not kept
	r.add(ctx, mk(KindNWCRequest, "req3", now))

	drain := func(f nostr.Filter) []string {
		ch, err := r.query(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if ch == nil {
			t.Fatal("query returned a nil channel: khatru's expiration scan would block on it forever")
		}
		var ids []string
		for ev := range ch {
			ids = append(ids, ev.ID)
		}
		return ids
	}
	// The filter Damus uses: this reply, to me, from the wallet service.
	damus := nostr.Filter{Kinds: []int{KindNWCResponse}, Authors: []string{"svc"}, Tags: nostr.TagMap{"e": []string{"req1"}, "p": []string{"client"}}}
	if got := drain(damus); len(got) != 1 || got[0] != "req1-reply" {
		t.Fatalf("late subscriber got %v", got)
	}
	// Someone else's request id, or another kind, matches nothing.
	if got := drain(nostr.Filter{Kinds: []int{KindNWCResponse}, Tags: nostr.TagMap{"e": []string{"other"}}}); len(got) != 0 {
		t.Fatalf("unrelated filter got %v", got)
	}
	if got := drain(nostr.Filter{Kinds: []int{KindNWCNotify}}); len(got) != 0 {
		t.Fatalf("notifications are not kept, got %v", got)
	}
	// Core resubscribing for requests gets the one it missed.
	if got := drain(nostr.Filter{Kinds: []int{KindNWCRequest}, Tags: nostr.TagMap{"p": []string{"client"}}}); len(got) != 1 || got[0] != "req3-reply" {
		t.Fatalf("core's resubscription got %v", got)
	}
	// An empty filter — what the relay's own startup scan sends — gets a
	// closed channel and nothing in it.
	if got := drain(nostr.Filter{}); len(got) != 0 {
		t.Fatalf("empty filter got %v", got)
	}
	// After the window it is gone.
	now = now.Add(RecentTTL + 2*time.Second)
	if got := drain(damus); len(got) != 0 {
		t.Fatalf("reply outlived its window: %v", got)
	}
	// Bounded: the oldest make room.
	for i := 0; i < RecentMax+10; i++ {
		r.add(ctx, mk(KindNWCResponse, "bulk", now))
	}
	if len(r.events) != RecentMax {
		t.Fatalf("buffer holds %d, cap is %d", len(r.events), RecentMax)
	}
}

// The size limit is per kind: a wallet service's reply may be large (a page
// of transactions with their zap requests), nothing a stranger can send may.
func TestEventSizeByKind(t *testing.T) {
	ctx := context.Background()
	big := func(kind, n int) *nostr.Event {
		return &nostr.Event{Kind: kind, Content: strings.Repeat("a", n), Tags: nostr.Tags{{"p", "client"}}}
	}
	for _, tc := range []struct {
		name   string
		ev     *nostr.Event
		reject bool
	}{
		{"request under 16 KiB", big(KindNWCRequest, 15<<10), false},
		{"request over 16 KiB", big(KindNWCRequest, 17<<10), true},
		{"zap receipt over 16 KiB", big(KindZapReceipt, 17<<10), true},
		{"info event over 16 KiB", big(KindNWCInfo, 17<<10), true},
		{"the reply that was refused on the node", big(KindNWCResponse, 40<<10), false},
		{"reply at the largest list_transactions page", big(KindNWCResponse, 88<<10), false},
		{"notification, same allowance", big(KindNWCNotify04, 40<<10), false},
		{"reply over the service limit", big(KindNWCResponse, 97<<10), true},
	} {
		if reject, _ := eventSizePolicy(ctx, tc.ev); reject != tc.reject {
			t.Errorf("%s: rejected=%v, want %v", tc.name, reject, tc.reject)
		}
	}
	if MaxServiceEventBytes >= MaxFrameBytes {
		t.Fatal("an event the policy allows must fit the WebSocket frame limit")
	}
}

// The buffer is bounded in bytes as well as in events.
func TestRecentRepliesByteCap(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := newRecentReplies()
	r.now = func() time.Time { return now }
	content := strings.Repeat("a", MaxServiceEventBytes)
	n := RecentMaxBytes/MaxServiceEventBytes + 10
	for i := 0; i < n; i++ {
		r.add(context.Background(), &nostr.Event{ID: fmt.Sprint(i), Kind: KindNWCResponse, CreatedAt: nostr.Timestamp(now.Unix()), Content: content})
	}
	if r.bytes > RecentMaxBytes || len(r.events) != RecentMaxBytes/MaxServiceEventBytes {
		t.Fatalf("held %d bytes in %d events, cap %d", r.bytes, len(r.events), RecentMaxBytes)
	}
	if r.events[len(r.events)-1].ID != fmt.Sprint(n-1) {
		t.Fatal("the newest reply must be the one kept")
	}
	now = now.Add(2 * RecentTTL)
	r.add(context.Background(), &nostr.Event{ID: "last", Kind: KindNWCResponse, CreatedAt: nostr.Timestamp(now.Unix()), Content: "x"})
	if len(r.events) != 1 || r.bytes != 1 {
		t.Fatalf("after expiry: %d events, %d bytes", len(r.events), r.bytes)
	}
}

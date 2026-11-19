package relay

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestStoreReplaceQuery(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	mk := func(kind int, ts nostr.Timestamp, content string) *nostr.Event {
		ev := &nostr.Event{Kind: kind, CreatedAt: ts, Content: content, Tags: nostr.Tags{{"p", pk}}}
		_ = ev.Sign(sk)
		return ev
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.SaveEvent(ctx, mk(KindZapReceipt, nostr.Timestamp(1000+i), "r")); err != nil {
			t.Fatal(err)
		}
	}
	old := mk(KindNWCInfo, 10, "old")
	newer := mk(KindNWCInfo, 20, "new")
	_ = s.ReplaceEvent(ctx, old)
	_ = s.ReplaceEvent(ctx, newer)
	_ = s.ReplaceEvent(ctx, old) // must not regress
	ch, _ := s.QueryEvents(ctx, nostr.Filter{Kinds: []int{KindNWCInfo}, Authors: []string{pk}})
	var infos []*nostr.Event
	for ev := range ch {
		infos = append(infos, ev)
	}
	if len(infos) != 1 || infos[0].Content != "new" {
		t.Fatalf("replaceable handling wrong: %+v", infos)
	}
	ch, _ = s.QueryEvents(ctx, nostr.Filter{Kinds: []int{KindZapReceipt}, Tags: nostr.TagMap{"p": []string{pk}}, Limit: 2})
	n := 0
	var last nostr.Timestamp = 1 << 40
	for ev := range ch {
		if ev.CreatedAt > last {
			t.Fatal("not newest first")
		}
		last = ev.CreatedAt
		n++
	}
	if n != 2 {
		t.Fatalf("limit not applied: %d", n)
	}
	if err := s.SaveEvent(ctx, infos[0]); err == nil {
		t.Fatal("duplicate id should be reported")
	}
}

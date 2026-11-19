package core

import (
	"context"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Publisher fans events out to relays with a shared connection pool.
type Publisher struct {
	pool *nostr.SimplePool
	log  *slog.Logger
}

// NewPublisher builds a pool.
func NewPublisher(log *slog.Logger) *Publisher {
	return &Publisher{pool: nostr.NewSimplePool(context.Background()), log: log}
}

// Pool exposes the pool for subscriptions (NWC).
func (p *Publisher) Pool() *nostr.SimplePool { return p.pool }

// Publish sends ev to every relay and returns the relays that accepted it.
func (p *Publisher) Publish(ctx context.Context, relays []string, ev *nostr.Event) []string {
	if len(relays) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var ok, failed []string
	for res := range p.pool.PublishMany(ctx, relays, *ev) {
		if res.Error != nil {
			failed = append(failed, res.RelayURL+": "+res.Error.Error())
			continue
		}
		ok = append(ok, res.RelayURL)
	}
	// Every event this service signs is logged once, with where it went:
	// the trace that makes zaps and NWC debuggable from the service log.
	p.log.Info("nostr: published", "kind", ev.Kind, "id", ev.ID, "pubkey", ev.PubKey, "p", firstTag(ev, "p"), "e", firstTag(ev, "e"), "ok", ok, "failed", failed)
	return ok
}

// firstTag returns the value of the first tag named name, or "".
func firstTag(ev *nostr.Event, name string) string {
	if t := ev.Tags.GetFirst([]string{name, ""}); t != nil && len(*t) >= 2 {
		return (*t)[1]
	}
	return ""
}

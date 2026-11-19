package relay

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"

	"github.com/lundog/lightning-identity-startos/service/internal/identity"
)

// Kinds the relay accepts, and nothing else.
const (
	KindNWCInfo     = 13194
	KindNWCRequest  = 23194
	KindNWCResponse = 23195
	KindNWCNotify   = 23197 // notification, NIP-44
	KindNWCNotify04 = 23196 // the same notification for legacy clients, NIP-04
	KindZapReceipt  = 9735
	MaxEventBytes   = 16 << 10 // an EVENT anyone else may send: an NWC request is a few hundred bytes, a receipt a few KiB
	// An EVENT this service's own wallet keys may send (kinds 23195-23197,
	// which authorPolicy admits from nobody else). A list_transactions
	// reply carries up to 50 entries, each with its zap request, and ran
	// past 16 KiB with a dozen zaps in the history: the relay refused its
	// own service's answer and the wallet's history stayed empty. Sized
	// for nwc.MaxResultBytes after encryption and base64.
	MaxServiceEventBytes = 96 << 10
	MaxFrameBytes        = 256 << 10 // a WebSocket message a client may send: clients like Damus open their ordinary timeline REQs on every relay in their pool, and a follow list runs far past 16 KiB; the read limit closes the socket, which looked like a flapping connection
	MaxConnections       = 256
	MaxSubsPerClient     = 8
)

// Options configures the relay.
type Options struct {
	Name        string
	Description string
	ServiceURL  string // wss://domain/relay
	Contact     string
	Identities  *identity.Watcher
	Store       *Store
	Log         *log.Logger
}

// New builds the khatru relay with this service's policies.
func New(o Options) *khatru.Relay {
	rl := khatru.NewRelay()
	rl.ServiceURL = o.ServiceURL
	rl.Info.Name = o.Name
	rl.Info.Description = o.Description
	rl.Info.Contact = o.Contact
	rl.Info.Software = "https://github.com/lundog/lightning-identity-startos"
	rl.Info.SupportedNIPs = []any{1, 11, 40, 47, 57}
	rl.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxMessageLength: MaxFrameBytes,
		MaxContentLength: MaxEventBytes,
		MaxSubscriptions: MaxSubsPerClient,
		MaxLimit:         MaxLimit,
		DefaultLimit:     DefaultLimit,
		RestrictedWrites: true,
	}
	rl.MaxMessageSize = MaxFrameBytes
	if o.Log != nil {
		rl.Log = o.Log
	}
	// Connection lifecycle, with the IP: a client that flaps shows up here
	// as open/close pairs, which is how the frame-limit problem was found.
	rl.OnConnect = append(rl.OnConnect, func(ctx context.Context) {
		rl.Log.Printf("nostr: websocket open ip=%s", khatru.GetIP(ctx))
	})
	rl.OnDisconnect = append(rl.OnDisconnect, func(ctx context.Context) {
		rl.Log.Printf("nostr: websocket closed ip=%s", khatru.GetIP(ctx))
	})

	var conns int64
	rl.RejectConnection = append(rl.RejectConnection,
		policies.ConnectionRateLimiter(10, time.Minute, 30),
		func(r *http.Request) bool { return atomic.LoadInt64(&conns) >= MaxConnections },
	)
	rl.OnConnect = append(rl.OnConnect, func(ctx context.Context) { atomic.AddInt64(&conns, 1) })
	rl.OnDisconnect = append(rl.OnDisconnect, func(ctx context.Context) { atomic.AddInt64(&conns, -1) })

	// khatru verifies signatures before any hook runs. The kind restriction
	// is the cheapest hook, so it goes first. The chain is wrapped so that
	// every event — accepted or not — is logged once with the verdict: the
	// relay's log is the trace for "my wallet sent a request and nothing
	// happened".
	checks := []func(ctx context.Context, ev *nostr.Event) (bool, string){
		eventSizePolicy, // cheapest first: the frame limit is generous, the event limit is not
		policies.RestrictToSpecifiedKinds(true,
			KindNWCInfo, KindNWCRequest, KindNWCResponse,
			KindNWCNotify, KindNWCNotify04, KindZapReceipt),
		policies.PreventLargeTags(2048),
		policies.PreventTooManyIndexableTags(16, []int{KindZapReceipt}, nil),
		policies.PreventTimestampsInThePast(2 * time.Hour),
		policies.PreventTimestampsInTheFuture(15 * time.Minute),
		policies.EventIPRateLimiter(30, time.Minute, 60),
		expiredPolicy, // NIP-40: never accept an event that has already expired
		authorPolicy(o.Identities),
	}
	rl.RejectEvent = append(rl.RejectEvent, func(ctx context.Context, ev *nostr.Event) (bool, string) {
		ip := khatru.GetIP(ctx)
		for _, check := range checks {
			if reject, msg := check(ctx, ev); reject {
				rl.Log.Printf("nostr: rejected kind=%d id=%s pubkey=%s p=%s ip=%s reason=%q", ev.Kind, ev.ID, ev.PubKey, firstTag(ev, "p"), ip, msg)
				return true, msg
			}
		}
		rl.Log.Printf("nostr: accepted kind=%d id=%s pubkey=%s p=%s e=%s ip=%s", ev.Kind, ev.ID, ev.PubKey, firstTag(ev, "p"), firstTag(ev, "e"), ip)
		return false, ""
	})
	rl.RejectFilter = append(rl.RejectFilter,
		policies.NoComplexFilters,
		policies.NoSearchQueries,
		policies.FilterIPRateLimiter(60, time.Minute, 120),
		func(ctx context.Context, f nostr.Filter) (bool, string) {
			if f.Limit > MaxLimit {
				return true, "blocked: limit too high"
			}
			return false, ""
		},
	)
	rl.OverwriteFilter = append(rl.OverwriteFilter, func(ctx context.Context, f *nostr.Filter) {
		if f.Limit <= 0 || f.Limit > MaxLimit {
			f.Limit = DefaultLimit
		}
	})
	rl.StoreEvent = append(rl.StoreEvent, o.Store.SaveEvent)
	rl.ReplaceEvent = append(rl.ReplaceEvent, o.Store.ReplaceEvent)
	rl.DeleteEvent = append(rl.DeleteEvent, o.Store.DeleteEvent)
	rl.QueryEvents = append(rl.QueryEvents, o.Store.QueryEvents)
	// Wallet requests and replies are held in memory for a minute, so that
	// neither an app that asks first and subscribes second, nor core while
	// its subscription restarts, misses a message (recent.go).
	recent := newRecentReplies()
	rl.OnEphemeralEvent = append(rl.OnEphemeralEvent, recent.add)
	rl.QueryEvents = append(rl.QueryEvents, recent.query)
	rl.CountEvents = append(rl.CountEvents, o.Store.CountEvents)
	return rl
}

// authorPolicy ties every accepted kind to the keys the identity document
// names: NWC requests only from paired clients addressed to their own service
// pubkey, NWC info/responses/notifications only from service pubkeys, zap
// receipts only from zap-signing keys. Nothing else is accepted: this is not
// a home for anyone's notes, profile or relay list — it carries ephemeral
// NWC traffic, the replaceable NWC info event and zap receipts.
func authorPolicy(w *identity.Watcher) func(ctx context.Context, ev *nostr.Event) (bool, string) {
	return func(ctx context.Context, ev *nostr.Event) (bool, string) {
		doc := w.Doc()
		switch ev.Kind {
		case KindNWCRequest:
			target := ev.Tags.GetFirst([]string{"p", ""})
			if target == nil || len(*target) < 2 {
				return true, "blocked: NWC request without p tag"
			}
			for _, c := range doc.NWCClients {
				if c.ClientPubkey == ev.PubKey && c.ServicePubkey == (*target)[1] {
					return false, ""
				}
			}
			return true, "restricted: unknown NWC client"
		case KindNWCInfo, KindNWCResponse, KindNWCNotify, KindNWCNotify04:
			for _, e := range doc.Identities {
				if e.NWCPubkey == ev.PubKey {
					return false, ""
				}
			}
			return true, "restricted: not a wallet service key"
		case KindZapReceipt:
			for _, e := range doc.Identities {
				if e.ZapPubkey == ev.PubKey {
					return false, ""
				}
			}
			return true, "restricted: not a zap signing key"
		}
		return true, "blocked: kind not accepted"
	}
}

// firstTag returns the value of the first tag named name, or "".
func firstTag(ev *nostr.Event, name string) string {
	if t := ev.Tags.GetFirst([]string{name, ""}); t != nil && len(*t) >= 2 {
		return (*t)[1]
	}
	return ""
}

// expiredPolicy rejects events whose NIP-40 expiration tag is in the past.
// khatru expires stored events on time; this closes the gap for events that
// arrive already dead, including ephemeral ones it never stores.
func expiredPolicy(ctx context.Context, ev *nostr.Event) (bool, string) {
	t := ev.Tags.GetFirst([]string{"expiration", ""})
	if t == nil || len(*t) < 2 {
		return false, ""
	}
	secs, err := strconv.ParseInt(strings.TrimSpace((*t)[1]), 10, 64)
	if err != nil || secs <= 0 {
		return true, "invalid: expiration tag is not a unix timestamp"
	}
	if time.Now().Unix() > secs {
		return true, "blocked: event has expired"
	}
	return false, ""
}

// eventSizePolicy bounds an accepted EVENT by its serialized size.
func eventSizePolicy(ctx context.Context, ev *nostr.Event) (bool, string) {
	limit := maxEventBytes(ev.Kind)
	if len(ev.Content) > limit {
		return true, "invalid: event too large"
	}
	n := len(ev.Content)
	for _, t := range ev.Tags {
		for _, v := range t {
			n += len(v) + 4
		}
	}
	if n > limit {
		return true, "invalid: event too large"
	}
	return false, ""
}

// maxEventBytes is the size limit for an event of a kind. The larger one is
// for the kinds only a wallet service key may publish; the author check
// that enforces "only" runs later in the same chain.
func maxEventBytes(kind int) int {
	switch kind {
	case KindNWCResponse, KindNWCNotify, KindNWCNotify04:
		return MaxServiceEventBytes
	}
	return MaxEventBytes
}

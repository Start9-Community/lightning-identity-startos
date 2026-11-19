// Package relay is the embedded, policy-locked Nostr relay the edge serves at
// /relay. It accepts only the kinds this service needs, only from the keys
// this service knows, stores only what NIP-01 says is storable, and bounds
// every anonymous connection.
package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fiatjaf/eventstore"
	"github.com/nbd-wtf/go-nostr"
	bolt "go.etcd.io/bbolt"
)

var (
	bEvents = []byte("events")      // id -> event JSON
	bByTime = []byte("by_time")     // ^created_at(8) + id -> ""
	bRepl   = []byte("replaceable") // kind:pubkey -> id
)

// Query limits.
const (
	DefaultLimit = 100
	MaxLimit     = 500
	MaxScan      = 20_000
)

// Store is a minimal bbolt event store for the few retained kinds.
type Store struct {
	db *bolt.DB
}

// OpenStore opens or creates the relay database.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bEvents, bByTime, bRepl} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func timeKey(created nostr.Timestamp, id string) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ^uint64(created))
	return append(ts[:], id...)
}

func replKey(kind int, pubkey string) []byte { return []byte(fmt.Sprintf("%d:%s", kind, pubkey)) }

// SaveEvent stores a regular event; a duplicate id is reported as
// eventstore.ErrDupEvent so khatru answers "duplicate" without re-broadcast.
func (s *Store) SaveEvent(ctx context.Context, ev *nostr.Event) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		evs := tx.Bucket(bEvents)
		if evs.Get([]byte(ev.ID)) != nil {
			return eventstore.ErrDupEvent
		}
		return s.putLocked(tx, ev)
	})
}

func (s *Store) putLocked(tx *bolt.Tx, ev *nostr.Event) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if err := tx.Bucket(bEvents).Put([]byte(ev.ID), raw); err != nil {
		return err
	}
	return tx.Bucket(bByTime).Put(timeKey(ev.CreatedAt, ev.ID), []byte{})
}

// ReplaceEvent stores a replaceable event, dropping the previous one of the
// same kind and author unless it is newer.
func (s *Store) ReplaceEvent(ctx context.Context, ev *nostr.Event) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		repl := tx.Bucket(bRepl)
		key := replKey(ev.Kind, ev.PubKey)
		if oldID := repl.Get(key); oldID != nil {
			var old nostr.Event
			if raw := tx.Bucket(bEvents).Get(oldID); raw != nil {
				if json.Unmarshal(raw, &old) == nil && old.CreatedAt > ev.CreatedAt {
					return nil // keep the newer one we already have
				}
				_ = tx.Bucket(bByTime).Delete(timeKey(old.CreatedAt, old.ID))
				_ = tx.Bucket(bEvents).Delete(oldID)
			}
		}
		if err := repl.Put(key, []byte(ev.ID)); err != nil {
			return err
		}
		return s.putLocked(tx, ev)
	})
}

// DeleteEvent removes an event by id.
func (s *Store) DeleteEvent(ctx context.Context, ev *nostr.Event) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bEvents).Get([]byte(ev.ID))
		if raw == nil {
			return nil
		}
		var old nostr.Event
		if err := json.Unmarshal(raw, &old); err != nil {
			return err
		}
		_ = tx.Bucket(bByTime).Delete(timeKey(old.CreatedAt, old.ID))
		if nostr.IsReplaceableKind(old.Kind) {
			_ = tx.Bucket(bRepl).Delete(replKey(old.Kind, old.PubKey))
		}
		return tx.Bucket(bEvents).Delete([]byte(ev.ID))
	})
}

// QueryEvents streams matches newest first, bounded by the filter's limit.
func (s *Store) QueryEvents(ctx context.Context, f nostr.Filter) (chan *nostr.Event, error) {
	limit := f.Limit
	if limit <= 0 || limit > MaxLimit {
		limit = DefaultLimit
	}
	out := make(chan *nostr.Event, 16)
	go func() {
		defer close(out)
		_ = s.db.View(func(tx *bolt.Tx) error {
			evs := tx.Bucket(bEvents)
			// Direct id lookups skip the scan.
			if len(f.IDs) > 0 {
				for _, id := range f.IDs {
					raw := evs.Get([]byte(id))
					if raw == nil {
						continue
					}
					var ev nostr.Event
					if json.Unmarshal(raw, &ev) == nil && f.Matches(&ev) {
						select {
						case out <- &ev:
						case <-ctx.Done():
							return nil
						}
					}
				}
				return nil
			}
			c := tx.Bucket(bByTime).Cursor()
			var start []byte
			if f.Until != nil {
				start = timeKey(*f.Until, "")
			}
			sent, scanned := 0, 0
			var k []byte
			if start != nil {
				k, _ = c.Seek(start)
			} else {
				k, _ = c.First()
			}
			for ; k != nil; k, _ = c.Next() {
				scanned++
				if scanned > MaxScan {
					return nil
				}
				created := nostr.Timestamp(^binary.BigEndian.Uint64(k[:8]))
				if f.Since != nil && created < *f.Since {
					return nil
				}
				raw := evs.Get(k[8:])
				if raw == nil {
					continue
				}
				var ev nostr.Event
				if err := json.Unmarshal(raw, &ev); err != nil || !f.Matches(&ev) {
					continue
				}
				select {
				case out <- &ev:
				case <-ctx.Done():
					return nil
				}
				sent++
				if sent >= limit {
					return nil
				}
			}
			return nil
		})
	}()
	return out, nil
}

// CountEvents answers COUNT with a bounded scan.
func (s *Store) CountEvents(ctx context.Context, f nostr.Filter) (int64, error) {
	ch, err := s.QueryEvents(ctx, nostr.Filter{IDs: f.IDs, Kinds: f.Kinds, Authors: f.Authors, Tags: f.Tags, Since: f.Since, Until: f.Until, Limit: MaxLimit})
	if err != nil {
		return 0, err
	}
	var n int64
	for range ch {
		n++
	}
	return n, nil
}

// Sweep deletes retained events older than keep (zap receipts only; profile
// and NWC info events are replaceable and never expire).
func (s *Store) Sweep(keep time.Duration) (int, error) {
	cutoff := nostr.Timestamp(time.Now().Add(-keep).Unix())
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bByTime).Cursor()
		var victims [][]byte
		for k, _ := c.Seek(timeKey(cutoff, "")); k != nil; k, _ = c.Next() {
			raw := tx.Bucket(bEvents).Get(k[8:])
			if raw == nil {
				victims = append(victims, bytes.Clone(k))
				continue
			}
			var ev nostr.Event
			if json.Unmarshal(raw, &ev) == nil && nostr.IsRegularKind(ev.Kind) {
				victims = append(victims, bytes.Clone(k))
			}
		}
		for _, k := range victims {
			_ = tx.Bucket(bEvents).Delete(k[8:])
			_ = tx.Bucket(bByTime).Delete(k)
			removed++
		}
		return nil
	})
	if errors.Is(err, bolt.ErrDatabaseNotOpen) {
		return removed, nil
	}
	return removed, err
}

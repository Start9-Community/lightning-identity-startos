package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bIdentities  = []byte("identities")   // id -> Identity
	bNames       = []byte("names")        // name -> id
	bConnections = []byte("connections")  // id -> Connection
	bConnByPK    = []byte("conn_by_pk")   // client pubkey -> connection id
	bInvoices    = []byte("invoices")     // payment hash -> Invoice
	bInvByIdent  = []byte("inv_by_ident") // identity id + 0x00 + inv(created unix nano) + hash -> ""
	bPendingZaps = []byte("pending_zaps") // payment hash -> ""
	bMeta        = []byte("meta")         // "meta" -> Meta
)

// ErrNotFound is returned for a missing record.
var ErrNotFound = errors.New("not found")

// ErrNameTaken is returned when an identity name already exists.
var ErrNameTaken = errors.New("name already in use")

// Store wraps the bbolt database.
type Store struct {
	db *bolt.DB
}

// Open opens or creates the database file.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bIdentities, bNames, bConnections, bConnByPK, bInvoices, bInvByIdent, bPendingZaps, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	st := &Store{db: db}
	if err := st.ensurePaymentBuckets(); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func put(b *bolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func get(b *bolt.Bucket, key string, v any) error {
	raw := b.Get([]byte(key))
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, v)
}

// ---- identities ----

// PutIdentity inserts or updates an identity, keeping the name index unique.
func (s *Store) PutIdentity(id *Identity) error {
	id.Name = strings.ToLower(strings.TrimSpace(id.Name))
	return s.db.Update(func(tx *bolt.Tx) error {
		names := tx.Bucket(bNames)
		if owner := names.Get([]byte(id.Name)); owner != nil && string(owner) != id.ID {
			return ErrNameTaken
		}
		var old Identity
		if err := get(tx.Bucket(bIdentities), id.ID, &old); err == nil && old.Name != id.Name {
			_ = names.Delete([]byte(old.Name))
		}
		if err := names.Put([]byte(id.Name), []byte(id.ID)); err != nil {
			return err
		}
		return put(tx.Bucket(bIdentities), id.ID, id)
	})
}

// GetIdentity fetches by id.
func (s *Store) GetIdentity(id string) (*Identity, error) {
	var out Identity
	err := s.db.View(func(tx *bolt.Tx) error { return get(tx.Bucket(bIdentities), id, &out) })
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetIdentityByName fetches by local-part name.
func (s *Store) GetIdentityByName(name string) (*Identity, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var out Identity
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bNames).Get([]byte(name))
		if id == nil {
			return ErrNotFound
		}
		return get(tx.Bucket(bIdentities), string(id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListIdentities returns every identity sorted by name.
func (s *Store) ListIdentities() ([]*Identity, error) {
	var out []*Identity
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bIdentities).ForEach(func(_, v []byte) error {
			var id Identity
			if err := json.Unmarshal(v, &id); err != nil {
				return err
			}
			out = append(out, &id)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// DeleteIdentity removes an identity and its name; connections and invoices
// stay (revoked / historical) so the ledger keeps its referents.
func (s *Store) DeleteIdentity(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var old Identity
		if err := get(tx.Bucket(bIdentities), id, &old); err != nil {
			return err
		}
		_ = tx.Bucket(bNames).Delete([]byte(old.Name))
		now := time.Now().UTC()
		conns := tx.Bucket(bConnections)
		if err := conns.ForEach(func(k, v []byte) error {
			var c Connection
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			if c.IdentityID == id && c.RevokedAt == nil {
				c.RevokedAt = &now
				return put(conns, c.ID, &c)
			}
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bIdentities).Delete([]byte(id))
	})
}

// ---- connections ----

// PutConnection inserts or updates a connection and its pubkey index.
func (s *Store) PutConnection(c *Connection) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bConnByPK).Put([]byte(c.ClientPubkey), []byte(c.ID)); err != nil {
			return err
		}
		return put(tx.Bucket(bConnections), c.ID, c)
	})
}

// GetConnection fetches by id.
func (s *Store) GetConnection(id string) (*Connection, error) {
	var out Connection
	err := s.db.View(func(tx *bolt.Tx) error { return get(tx.Bucket(bConnections), id, &out) })
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetConnectionByClient fetches by client pubkey.
func (s *Store) GetConnectionByClient(pubkey string) (*Connection, error) {
	var out Connection
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bConnByPK).Get([]byte(pubkey))
		if id == nil {
			return ErrNotFound
		}
		return get(tx.Bucket(bConnections), string(id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListConnections returns connections, optionally filtered by identity,
// newest first.
func (s *Store) ListConnections(identityID string) ([]*Connection, error) {
	var out []*Connection
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bConnections).ForEach(func(_, v []byte) error {
			var c Connection
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			if identityID == "" || c.IdentityID == identityID {
				out = append(out, &c)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, err
}

// ---- invoices ----

func invIndexKey(identityID string, created time.Time, hash string) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ^uint64(created.UnixNano())) // newest first
	k := make([]byte, 0, len(identityID)+1+8+len(hash))
	k = append(k, identityID...)
	k = append(k, 0)
	k = append(k, ts[:]...)
	return append(k, hash...)
}

// UpdateInvoice applies fn to the stored invoice inside one write
// transaction, so a state change is decided against the row as it is, not as
// a caller read it a moment ago. fn returns false to leave the row alone.
// Used for every state transition: a settlement and a cancellation racing
// each other must not both win.
func (s *Store) UpdateInvoice(hash string, fn func(inv *Invoice) bool) (*Invoice, error) {
	var out Invoice
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := get(tx.Bucket(bInvoices), hash, &out); err != nil {
			return err
		}
		if !fn(&out) {
			return nil
		}
		return putInvoiceTx(tx, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PutInvoice inserts or updates an invoice and its indexes.
func (s *Store) PutInvoice(inv *Invoice) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putInvoiceTx(tx, inv) })
}

func putInvoiceTx(tx *bolt.Tx, inv *Invoice) error {
	if err := tx.Bucket(bInvByIdent).Put(invIndexKey(inv.IdentityID, inv.CreatedAt, inv.PaymentHash), []byte{}); err != nil {
		return err
	}
	pz := tx.Bucket(bPendingZaps)
	if inv.ZapRequest != "" && inv.State == InvoiceOpen {
		if err := pz.Put([]byte(inv.PaymentHash), []byte{}); err != nil {
			return err
		}
	} else if inv.ZapRequest != "" && inv.State == InvoiceSettled && inv.ReceiptID == "" {
		// keep pending until the receipt is out
		if err := pz.Put([]byte(inv.PaymentHash), []byte{}); err != nil {
			return err
		}
	} else {
		_ = pz.Delete([]byte(inv.PaymentHash))
	}
	return put(tx.Bucket(bInvoices), inv.PaymentHash, inv)
}

// GetInvoice fetches by payment hash (hex).
func (s *Store) GetInvoice(hash string) (*Invoice, error) {
	var out Invoice
	err := s.db.View(func(tx *bolt.Tx) error { return get(tx.Bucket(bInvoices), hash, &out) })
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListInvoices returns an identity's invoices newest first, up to limit,
// skipping offset.
func (s *Store) ListInvoices(identityID string, offset, limit int) ([]*Invoice, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*Invoice
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bInvByIdent).Cursor()
		prefix := append([]byte(identityID), 0)
		inv := tx.Bucket(bInvoices)
		n := 0
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if n < offset {
				n++
				continue
			}
			hash := string(k[len(prefix)+8:])
			var i Invoice
			if err := get(inv, hash, &i); err != nil {
				continue
			}
			out = append(out, &i)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	return out, err
}

// PendingZaps lists payment hashes whose zap flow is not finished.
func (s *Store) PendingZaps() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bPendingZaps).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// OpenInvoices lists invoices still open (for expiry sweeps).
func (s *Store) OpenInvoices() ([]*Invoice, error) {
	var out []*Invoice
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bInvoices).ForEach(func(_, v []byte) error {
			var i Invoice
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if i.State == InvoiceOpen {
				out = append(out, &i)
			}
			return nil
		})
	})
	return out, err
}

// ---- meta ----

// GetMeta reads the bookkeeping record.
func (s *Store) GetMeta() (Meta, error) {
	var m Meta
	err := s.db.View(func(tx *bolt.Tx) error {
		err := get(tx.Bucket(bMeta), "meta", &m)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
	return m, err
}

// PutMeta writes the bookkeeping record.
func (s *Store) PutMeta(m Meta) error {
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx.Bucket(bMeta), "meta", m) })
}

// GetSettings reads the operator settings; ok is false when none were ever
// saved, so the caller applies its defaults.
func (s *Store) GetSettings() (Settings, bool, error) {
	var st Settings
	err := s.db.View(func(tx *bolt.Tx) error { return get(tx.Bucket(bMeta), "settings", &st) })
	if errors.Is(err, ErrNotFound) {
		return st, false, nil
	}
	return st, err == nil, err
}

// PutSettings writes the operator settings.
func (s *Store) PutSettings(st Settings) error {
	st.UpdatedAt = time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error { return put(tx.Bucket(bMeta), "settings", st) })
}

// Reseal re-encrypts every sealed field from old to new (master key rotation).
func (s *Store) Reseal(old, fresh *Sealer) error {
	reseal := func(v []byte) ([]byte, error) {
		if len(v) == 0 {
			return v, nil
		}
		pt, err := old.Open(v)
		if err != nil {
			return nil, err
		}
		return fresh.Seal(pt)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		ids := tx.Bucket(bIdentities)
		if err := ids.ForEach(func(k, v []byte) error {
			var id Identity
			if err := json.Unmarshal(v, &id); err != nil {
				return err
			}
			var err error
			if id.ZapSecretEnc, err = reseal(id.ZapSecretEnc); err != nil {
				return fmt.Errorf("identity %s zap key: %w", id.Name, err)
			}
			if id.NWCSecretEnc, err = reseal(id.NWCSecretEnc); err != nil {
				return fmt.Errorf("identity %s nwc key: %w", id.Name, err)
			}
			return put(ids, id.ID, &id)
		}); err != nil {
			return err
		}
		pays := tx.Bucket(bPayments)
		if err := pays.ForEach(func(k, v []byte) error {
			var p Payment
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if len(p.PreimageEnc) == 0 {
				return nil
			}
			var err error
			if p.PreimageEnc, err = reseal(p.PreimageEnc); err != nil {
				return err
			}
			return put(pays, p.PaymentHash, &p)
		}); err != nil {
			return err
		}
		invs := tx.Bucket(bInvoices)
		return invs.ForEach(func(k, v []byte) error {
			var inv Invoice
			if err := json.Unmarshal(v, &inv); err != nil {
				return err
			}
			if len(inv.PreimageEnc) == 0 {
				return nil
			}
			var err error
			if inv.PreimageEnc, err = reseal(inv.PreimageEnc); err != nil {
				return err
			}
			return put(invs, inv.PaymentHash, &inv)
		})
	})
}

// ---- payments ----

var (
	bPayments    = []byte("payments")     // payment hash -> Payment
	bPayByIdent  = []byte("pay_by_ident") // identity id + 0x00 + inv(created) + hash -> ""
	bPayByConn   = []byte("pay_by_conn")  // connection id + 0x00 + inv(created) + hash -> ""
	bAdjustments = []byte("adjustments")  // id -> Adjustment
	bAdjByIdent  = []byte("adj_by_ident") // identity id + 0x00 + inv(created) + id -> ""
)

func (s *Store) ensurePaymentBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bPayments, bPayByIdent, bPayByConn, bAdjustments, bAdjByIdent} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutPayment inserts or updates a payment and its indexes. There is one row
// per payment hash — a retry of a failed payment replaces it — so the old
// row's index entries are removed first: two entries for one row would count
// the payment twice in every balance and budget.
func (s *Store) PutPayment(p *Payment) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var old Payment
		if err := get(tx.Bucket(bPayments), p.PaymentHash, &old); err == nil {
			if !old.CreatedAt.Equal(p.CreatedAt) || old.IdentityID != p.IdentityID {
				_ = tx.Bucket(bPayByIdent).Delete(invIndexKey(old.IdentityID, old.CreatedAt, old.PaymentHash))
			}
			if !old.CreatedAt.Equal(p.CreatedAt) || old.ConnectionID != p.ConnectionID {
				_ = tx.Bucket(bPayByConn).Delete(invIndexKey(old.ConnectionID, old.CreatedAt, old.PaymentHash))
			}
		}
		if err := tx.Bucket(bPayByIdent).Put(invIndexKey(p.IdentityID, p.CreatedAt, p.PaymentHash), []byte{}); err != nil {
			return err
		}
		if err := tx.Bucket(bPayByConn).Put(invIndexKey(p.ConnectionID, p.CreatedAt, p.PaymentHash), []byte{}); err != nil {
			return err
		}
		return put(tx.Bucket(bPayments), p.PaymentHash, p)
	})
}

// GetPayment fetches by payment hash.
func (s *Store) GetPayment(hash string) (*Payment, error) {
	var out Payment
	err := s.db.View(func(tx *bolt.Tx) error { return get(tx.Bucket(bPayments), hash, &out) })
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPayments returns an identity's payments newest first.
func (s *Store) ListPayments(identityID string, offset, limit int) ([]*Payment, error) {
	return s.listPaymentsBy(bPayByIdent, identityID, offset, limit)
}

// ListConnectionPayments returns a connection's payments newest first.
func (s *Store) ListConnectionPayments(connectionID string, offset, limit int) ([]*Payment, error) {
	return s.listPaymentsBy(bPayByConn, connectionID, offset, limit)
}

func (s *Store) listPaymentsBy(index []byte, id string, offset, limit int) ([]*Payment, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*Payment
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(index).Cursor()
		prefix := append([]byte(id), 0)
		pays := tx.Bucket(bPayments)
		n := 0
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if n < offset {
				n++
				continue
			}
			var p Payment
			if err := get(pays, string(k[len(prefix)+8:]), &p); err != nil {
				continue
			}
			out = append(out, &p)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	return out, err
}

// ConnectionSpent sums a connection's settled and pending payments (amount
// plus fee, or fee limit while pending) since `since` (zero = all time).
func (s *Store) ConnectionSpent(connectionID string, since time.Time) (int64, error) {
	var sum int64
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bPayByConn).Cursor()
		prefix := append([]byte(connectionID), 0)
		pays := tx.Bucket(bPayments)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			var p Payment
			if err := get(pays, string(k[len(prefix)+8:]), &p); err != nil {
				continue
			}
			if !since.IsZero() && p.CreatedAt.Before(since) {
				break // newest first: everything after is older
			}
			switch p.State {
			case PaymentSettled:
				sum += p.AmountMsat + p.FeeMsat
			case PaymentPending:
				sum += p.AmountMsat + p.FeeLimitMsat
			}
		}
		return nil
	})
	return sum, err
}

// PendingPayments lists payments still pending (for reconciliation).
func (s *Store) PendingPayments() ([]*Payment, error) {
	var out []*Payment
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bPayments).ForEach(func(_, v []byte) error {
			var p Payment
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if p.State == PaymentPending {
				out = append(out, &p)
			}
			return nil
		})
	})
	return out, err
}

// ---- adjustments and balance ----

// PutAdjustment records an operator credit or debit.
func (s *Store) PutAdjustment(a *Adjustment) error {
	if a.AmountMsat == 0 {
		return errors.New("adjustment amount must not be zero")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bAdjByIdent).Put(invIndexKey(a.IdentityID, a.CreatedAt, a.ID), []byte{}); err != nil {
			return err
		}
		return put(tx.Bucket(bAdjustments), a.ID, a)
	})
}

// ListAdjustments returns an identity's adjustments newest first.
func (s *Store) ListAdjustments(identityID string, offset, limit int) ([]*Adjustment, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*Adjustment
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bAdjByIdent).Cursor()
		prefix := append([]byte(identityID), 0)
		adj := tx.Bucket(bAdjustments)
		n := 0
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if n < offset {
				n++
				continue
			}
			var a Adjustment
			if err := get(adj, string(k[len(prefix)+8:]), &a); err != nil {
				continue
			}
			out = append(out, &a)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	return out, err
}

// IdentityBalance folds an identity's whole ledger — settled invoices,
// settled and pending payments, operator adjustments — into one position,
// inside a single read transaction so the parts agree.
func (s *Store) IdentityBalance(identityID string) (Balance, error) {
	var b Balance
	prefix := append([]byte(identityID), 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bInvByIdent).Cursor()
		inv := tx.Bucket(bInvoices)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			var i Invoice
			if err := get(inv, string(k[len(prefix)+8:]), &i); err != nil || i.State != InvoiceSettled {
				continue
			}
			if i.AmtPaidMsat > 0 {
				b.Received += i.AmtPaidMsat
			} else {
				b.Received += i.AmountMsat
			}
		}
		c = tx.Bucket(bPayByIdent).Cursor()
		pays := tx.Bucket(bPayments)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			var p Payment
			if err := get(pays, string(k[len(prefix)+8:]), &p); err != nil {
				continue
			}
			switch p.State {
			case PaymentSettled:
				b.Sent += p.AmountMsat + p.FeeMsat
			case PaymentPending:
				b.InFlight += p.AmountMsat + p.FeeLimitMsat
			}
		}
		c = tx.Bucket(bAdjByIdent).Cursor()
		adj := tx.Bucket(bAdjustments)
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			var a Adjustment
			if err := get(adj, string(k[len(prefix)+8:]), &a); err != nil {
				continue
			}
			b.Adjusted += a.AmountMsat
		}
		return nil
	})
	b.Available = b.Received + b.Adjusted - b.Sent - b.InFlight
	return b, err
}

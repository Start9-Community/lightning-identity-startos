// Package identity is the document core publishes for edge: everything the
// public process needs to answer LNURL, NIP-05 and relay-policy questions, and
// nothing secret. Core writes it atomically; edge polls its mtime.
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FileName is the document's name inside the shared identities directory.
const FileName = "edge.json"

// Doc is the published document.
type Doc struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Domain      string      `json:"domain"`    // host part of every address
	BaseURL     string      `json:"base_url"`  // https://<domain>
	RelayURL    string      `json:"relay_url"` // wss://<domain>/relay
	Identities  []Entry     `json:"identities"`
	NWCClients  []NWCClient `json:"nwc_clients"`
}

// Entry is one identity as the public side sees it.
type Entry struct {
	Name           string   `json:"name"`
	DisplayName    string   `json:"display_name"`
	ZapPubkey      string   `json:"zap_pubkey"`
	NWCPubkey      string   `json:"nwc_pubkey"`
	UserPubkey     string   `json:"user_pubkey,omitempty"`
	NIP05          bool     `json:"nip05"`
	MinMsat        int64    `json:"min_msat"`
	MaxMsat        int64    `json:"max_msat"`
	CommentAllowed int      `json:"comment_allowed"`
	Relays         []string `json:"relays,omitempty"`
}

// NWCClient is a client pubkey allowed to send kind-23194 requests to a
// service pubkey.
type NWCClient struct {
	ClientPubkey  string `json:"client_pubkey"`
	ServicePubkey string `json:"service_pubkey"`
	Identity      string `json:"identity"`
}

// Lightning address of the entry.
func (d *Doc) Address(e *Entry) string { return e.Name + "@" + d.Domain }

// Find returns the entry for a name, or nil.
func (d *Doc) Find(name string) *Entry {
	name = strings.ToLower(name)
	for i := range d.Identities {
		if d.Identities[i].Name == name {
			return &d.Identities[i]
		}
	}
	return nil
}

var nameRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// ValidName reports whether a local part is acceptable: lowercase, the LUD-16
// character set, and `_` for the bare-domain NIP-05 name.
func ValidName(name string) bool {
	return name == "_" || nameRe.MatchString(name)
}

// Write stores the document atomically in dir.
func Write(dir string, d *Doc) error {
	d.GeneratedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, FileName+".tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FileName))
}

// Watcher reloads the document when its mtime changes.
type Watcher struct {
	path  string
	mu    sync.RWMutex
	doc   *Doc
	mtime time.Time
	size  int64
}

// NewWatcher loads the document once and returns a watcher; a missing file
// yields an empty document rather than an error so edge can start first.
func NewWatcher(dir string) *Watcher {
	w := &Watcher{path: filepath.Join(dir, FileName), doc: &Doc{}}
	_ = w.Reload()
	return w
}

// Reload re-reads the file if it changed.
func (w *Watcher) Reload() error {
	st, err := os.Stat(w.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	w.mu.RLock()
	same := st.ModTime().Equal(w.mtime) && st.Size() == w.size
	w.mu.RUnlock()
	if same {
		return nil
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}
	var d Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("parse %s: %w", w.path, err)
	}
	for i := range d.Identities {
		d.Identities[i].Name = strings.ToLower(d.Identities[i].Name)
	}
	w.mu.Lock()
	w.doc, w.mtime, w.size = &d, st.ModTime(), st.Size()
	w.mu.Unlock()
	return nil
}

// Doc returns the current document (never nil).
func (w *Watcher) Doc() *Doc {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.doc
}

// Run polls for changes until ctx is done.
func (w *Watcher) Run(stop <-chan struct{}, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := w.Reload(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

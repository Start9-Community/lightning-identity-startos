package nwc

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// zapTx is a settled incoming zap as list_transactions renders it: a BOLT11
// with a route hint and a kind-9734 request naming eleven relays, the shape
// that overflowed the relay's event limit on a real node.
func zapTx(i int) map[string]any {
	return map[string]any{
		"type": "incoming", "state": "settled",
		"invoice":          "lnbc10n1" + strings.Repeat("q", 520),
		"description":      "",
		"description_hash": strings.Repeat("ab", 32),
		"payment_hash":     fmt.Sprintf("%064d", i),
		"preimage":         strings.Repeat("cd", 32),
		"amount":           1000, "fees_paid": 0,
		"created_at": 1_800_000_000 - i, "settled_at": 1_800_000_000 - i, "expires_at": 1_800_003_600 - i,
		"metadata": map[string]any{"nostr": map[string]any{
			"id": strings.Repeat("1", 64), "pubkey": strings.Repeat("2", 64), "sig": strings.Repeat("3", 128),
			"kind": 9734, "created_at": 1_800_000_000 - i, "content": "⚡",
			"tags": [][]string{{"p", strings.Repeat("4", 64)}, {"e", strings.Repeat("5", 64)}, {"amount", "1000"},
				append([]string{"relays"}, strings.Fields(strings.Repeat("wss://relay.example.com/some/path ", 11))...)},
		}},
	}
}

func listSize(txs []map[string]any) int {
	b, _ := json.Marshal(map[string]any{"result_type": "list_transactions", "error": nil, "result": map[string]any{"transactions": txs}})
	return len(b)
}

func TestFitTransactions(t *testing.T) {
	mk := func(n int) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = zapTx(i)
		}
		return out
	}

	// A short history goes out whole.
	few := mk(5)
	out, full, slim, bare := fitTransactions(few, MaxResultBytes)
	if len(out) != 5 || full != 5 || slim != 0 || bare != 0 || out[0]["invoice"] == nil {
		t.Fatalf("a list that fits was changed: len=%d slim=%d bare=%d", len(out), slim, bare)
	}

	// Damus's page of 50 zaps does not fit whole. Every entry must still
	// arrive, the newest with the zap request a wallet names the zapper by.
	page := mk(50)
	if listSize(page) <= MaxResultBytes {
		t.Fatalf("test data too small to exercise trimming: %d bytes", listSize(page))
	}
	out, full, slim, bare = fitTransactions(page, MaxResultBytes)
	if got := listSize(out); got > MaxResultBytes {
		t.Fatalf("trimmed list is %d bytes, budget %d", got, MaxResultBytes)
	}
	if len(out) != 50 || full != 50 {
		t.Fatalf("entries dropped though plainer ones would have fit: %d of %d", len(out), full)
	}
	if slim != 50 {
		t.Fatalf("settled entries keep their BOLT11 only when everything fits: slim=%d", slim)
	}
	if out[0]["metadata"] == nil {
		t.Fatal("the newest entry lost its zap request")
	}
	if bare == 0 || out[49]["metadata"] != nil {
		t.Fatalf("expected the oldest entries to give up metadata first: bare=%d", bare)
	}
	for i := 1; i < len(out); i++ {
		if out[i-1]["metadata"] == nil && out[i]["metadata"] != nil {
			t.Fatalf("entry %d kept metadata while newer entry %d lost it", i, i-1)
		}
	}
	for _, tx := range out {
		if tx["payment_hash"] == nil || tx["preimage"] == nil || tx["amount"] == nil {
			t.Fatalf("an entry lost a field a history needs: %v", tx)
		}
	}

	// The tighter budget for an unknown relay holds too.
	out, _, _, _ = fitTransactions(mk(50), MaxResultBytesForeign)
	if got := listSize(out); got > MaxResultBytesForeign || len(out) != 50 {
		t.Fatalf("foreign budget: %d bytes, %d entries", got, len(out))
	}

	// An unpaid invoice keeps its BOLT11: it is the point of the entry.
	withPending := mk(50)
	withPending[0]["state"] = "pending"
	out, _, _, _ = fitTransactions(withPending, MaxResultBytes)
	if out[0]["invoice"] == nil {
		t.Fatal("a payable invoice lost its BOLT11")
	}

	// When even bare entries do not fit, the oldest go.
	out, full, _, _ = fitTransactions(mk(50), 4_000)
	if len(out) == 0 || len(out) >= 50 || full != 50 || listSize(out) > 4_000 {
		t.Fatalf("tiny budget: %d entries, %d bytes", len(out), listSize(out))
	}
	if out[0]["payment_hash"] != fmt.Sprintf("%064d", 0) {
		t.Fatal("truncation must keep the newest entries")
	}
}

// The budgets are only right if the encrypted event fits the relay: check
// the arithmetic the constants' comment claims.
func TestResultBudgetsFitAfterEncryption(t *testing.T) {
	sk := strings.Repeat("01", 32)
	pk := "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" // pubkey of secret key 1
	for _, tc := range []struct{ plain, eventLimit int }{
		{MaxResultBytes, 96 << 10},        // relay.MaxServiceEventBytes
		{MaxResultBytesForeign, 64 << 10}, // strfry's default
	} {
		for _, scheme := range []string{"nip44_v2", "nip04"} {
			content, err := encrypt(scheme, strings.Repeat("x", tc.plain), pk, sk)
			if err != nil {
				t.Fatalf("%s cannot encrypt %d bytes: %v", scheme, tc.plain, err)
			}
			if len(content)+1024 > tc.eventLimit {
				t.Errorf("%s: %d bytes of result become %d of content, over a %d-byte event", scheme, tc.plain, len(content), tc.eventLimit)
			}
			if len(content) > tc.plain*3/2 {
				t.Errorf("%s: %d bytes of content trips respond()'s own limit of %d", scheme, len(content), tc.plain*3/2)
			}
		}
	}
}

func TestRequestEncryption(t *testing.T) {
	for _, tc := range []struct {
		tags   nostr.Tags
		scheme string
		ok     bool
	}{
		{nostr.Tags{{"p", "x"}}, "nip04", true}, // no tag: the original protocol
		{nostr.Tags{{"encryption", "nip04"}}, "nip04", true},
		{nostr.Tags{{"encryption", "nip44_v2"}}, "nip44_v2", true},
		{nostr.Tags{{"encryption", "nip44"}}, "nip44", false}, // not a code the spec defines
		{nostr.Tags{{"encryption", "nip99_v7"}}, "nip99_v7", false},
		{nostr.Tags{{"encryption", strings.Repeat("z", 200)}}, strings.Repeat("z", 32), false},
	} {
		scheme, ok := requestEncryption(&nostr.Event{Tags: tc.tags})
		if scheme != tc.scheme || ok != tc.ok {
			t.Errorf("%v: got %q %v, want %q %v", tc.tags, scheme, ok, tc.scheme, tc.ok)
		}
	}
}

// Metadata is at most 4096 characters (NWC-06). When what this service
// assembles is larger, the zap request goes and the small facts stay.
func TestFitMetadata(t *testing.T) {
	size := func(m map[string]any) int { b, _ := json.Marshal(m); return len(b) }
	if fitMetadata(nil) != nil || fitMetadata(map[string]any{}) != nil {
		t.Fatal("no metadata should stay no metadata")
	}
	small := map[string]any{"comment": "gm", "nostr": map[string]any{"kind": 9734, "content": "zap"}}
	if got := fitMetadata(small); got == nil || got["nostr"] == nil || got["comment"] != "gm" {
		t.Fatalf("small metadata changed: %v", got)
	}
	big := map[string]any{"comment": "gm", "nostr": map[string]any{"kind": 9734, "content": strings.Repeat("z", 4090)}}
	got := fitMetadata(big)
	if got == nil || got["nostr"] != nil || got["comment"] != "gm" || size(got) > 4096 {
		t.Fatalf("oversize zap request: %v", got)
	}
	if got := fitMetadata(map[string]any{"note": strings.Repeat("y", 5000)}); got != nil {
		t.Fatalf("oversize metadata with nothing to shed must be dropped whole, got %d bytes", size(got))
	}
	if metadataObject(json.RawMessage(`{"a":1}`)) != `{"a":1}` || metadataObject(json.RawMessage(`[1]`)) != "" || metadataObject(json.RawMessage(`{}`)) != "" ||
		metadataObject(json.RawMessage(`{"a":"`+strings.Repeat("x", 4096)+`"}`)) != "" {
		t.Fatal("metadataObject accepts or rejects the wrong things")
	}
}

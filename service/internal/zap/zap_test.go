package zap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func signedRequest(t *testing.T, amount string, tags nostr.Tags) string {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	ev := nostr.Event{Kind: KindZapRequest, CreatedAt: nostr.Now(), Content: "zap!", Tags: tags}
	if amount != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"amount", amount})
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	return string(raw)
}

func TestValidateAndReceipt(t *testing.T) {
	recipient := nostr.GeneratePrivateKey()
	rpk, _ := nostr.GetPublicKey(recipient)
	raw := signedRequest(t, "21000", nostr.Tags{{"p", rpk}, {"relays", "wss://relay.example", "https://not-a-relay"}, {"e", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}})
	req, err := Validate(raw, 21000)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if req.Recipient != rpk || len(req.Relays) != 1 {
		t.Fatalf("parsed badly: %+v", req)
	}
	zapSK := nostr.GeneratePrivateKey()
	rec, err := Receipt(req, "lnbc1...", "00ff", time.Now(), zapSK)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := rec.CheckSignature(); !ok || rec.Kind != KindZapReceipt {
		t.Fatal("receipt not signed")
	}
	if rec.Tags.GetFirst([]string{"description"}) == nil || rec.Tags.GetFirst([]string{"P"}) == nil {
		t.Fatal("receipt missing tags")
	}
}

func TestValidateRejects(t *testing.T) {
	rpk, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	cases := map[string]string{
		"amount mismatch": signedRequest(t, "1000", nostr.Tags{{"p", rpk}, {"relays", "wss://r"}}),
		"no p":            signedRequest(t, "", nostr.Tags{{"relays", "wss://r"}}),
		"two p":           signedRequest(t, "", nostr.Tags{{"p", rpk}, {"p", rpk}, {"relays", "wss://r"}}),
		"no relays":       signedRequest(t, "", nostr.Tags{{"p", rpk}}),
		"garbage":         `{"kind":9734}`,
	}
	for name, raw := range cases {
		if _, err := Validate(raw, 21000); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// tampered signature
	raw := signedRequest(t, "", nostr.Tags{{"p", rpk}, {"relays", "wss://r"}})
	var ev nostr.Event
	_ = json.Unmarshal([]byte(raw), &ev)
	ev.Content = "changed"
	tampered, _ := json.Marshal(ev)
	if _, err := Validate(string(tampered), 21000); err == nil {
		t.Error("tampered request accepted")
	}
}

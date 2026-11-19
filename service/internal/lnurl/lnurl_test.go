package lnurl

import (
	"encoding/hex"
	"testing"
)

func TestMetadataHashStable(t *testing.T) {
	m := Metadata("alice@pay.example", "Alice")
	if m != `[["text/plain","Pay Alice (alice@pay.example)"],["text/identifier","alice@pay.example"]]` {
		t.Fatalf("metadata changed: %s", m)
	}
	if hex.EncodeToString(MetadataHash(m)) != hex.EncodeToString(MetadataHash(Metadata("alice@pay.example", "Alice"))) {
		t.Fatal("hash not deterministic")
	}
}

func TestBounds(t *testing.T) {
	min, max := ClampBounds(0, 0)
	if min != AbsoluteMinMsat || max != AbsoluteMaxMsat {
		t.Fatal("defaults")
	}
	min, max = ClampBounds(5000, 2000)
	if max != min {
		t.Fatal("inverted range not fixed")
	}
	if ValidateComment(0, "hi") == nil || ValidateComment(2, "hello") == nil || ValidateComment(5, "hello") != nil {
		t.Fatal("comment rules")
	}
	if _, err := ValidatePayerData(`{"name":"x"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePayerData(`[1]`); err == nil {
		t.Fatal("non-object payer data accepted")
	}
}

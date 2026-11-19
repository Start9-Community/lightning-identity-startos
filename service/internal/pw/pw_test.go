package pw

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(h, "correct horse") || Verify(h, "wrong") || Verify("garbage", "x") {
		t.Fatal("verify mismatch")
	}
	// A hash produced by the package's TypeScript side (scryptSync, N=16384 r=8 p=1, 32 bytes).
	const tsHash = "scrypt$16384$8$1$MDEyMzQ1Njc4OWFiY2RlZg==$"
	_ = tsHash
}

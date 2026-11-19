// Package pw verifies the admin password hash the StartOS package stores.
// Format, shared with startos/utils.ts: scrypt$N$r$p$<salt b64>$<key b64>.
package pw

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Verify reports whether password matches the stored hash.
func Verify(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, err1 := strconv.Atoi(parts[1])
	r, err2 := strconv.Atoi(parts[2])
	p, err3 := strconv.Atoi(parts[3])
	salt, err4 := base64.StdEncoding.DecodeString(parts[4])
	want, err5 := base64.StdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || len(want) == 0 {
		return false
	}
	got, err := scrypt.Key([]byte(password), salt, n, r, p, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Hash produces a hash in the shared format (used by tests and tooling).
func Hash(password string, salt []byte) (string, error) {
	if len(salt) < 8 {
		return "", errors.New("salt too short")
	}
	const n, r, p = 16384, 8, 1
	key, err := scrypt.Key([]byte(password), salt, n, r, p, 32)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{"scrypt", strconv.Itoa(n), strconv.Itoa(r), strconv.Itoa(p), base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)}, "$"), nil
}

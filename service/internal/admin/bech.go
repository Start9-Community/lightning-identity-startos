package admin

import (
	"errors"

	"github.com/nbd-wtf/go-nostr/nip19"
)

func encodeNpub(hexPK string) (string, error) { return nip19.EncodePublicKey(hexPK) }

func decodeNpub(npub string) (string, error) {
	prefix, v, err := nip19.Decode(npub)
	if err != nil {
		return "", err
	}
	if prefix != "npub" {
		return "", errors.New("not an npub")
	}
	s, ok := v.(string)
	if !ok {
		return "", errors.New("not an npub")
	}
	return s, nil
}

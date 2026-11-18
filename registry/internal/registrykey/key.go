package registrykey

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

var ErrMalformed = errors.New("malformed registry key file")

func LoadSeed(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	if len(s) != 64 {
		return nil, ErrMalformed
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, ErrMalformed
		}
	}
	seed, err := hex.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrMalformed
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

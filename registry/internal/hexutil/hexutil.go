package hexutil

import (
	"encoding/hex"
	"strings"
)

// DecodeFixedLower decodes a hex string of exactly wantLen bytes; result is lowercase hex.
func DecodeFixedLower(s string, wantLen int) (raw []byte, lower string, err error) {
	if len(s) != wantLen*2 {
		return nil, "", ErrInvalidHex
	}
	if !isHex(s) {
		return nil, "", ErrInvalidHex
	}
	raw = make([]byte, wantLen)
	if _, err := hex.Decode(raw, []byte(s)); err != nil {
		return nil, "", ErrInvalidHex
	}
	lower = strings.ToLower(s)
	return raw, lower, nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

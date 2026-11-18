package trust

import (
	"testing"
)

func TestRejectsSmallOrderKey(t *testing.T) {
	low := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := parseIssuer(IssuerJSON{
		Name:       "University of Waghi",
		KeyID:      "0000000000000000",
		PublicKey:  low,
		ValidFrom:  "2020-01-01T00:00:00Z",
		ValidUntil: nil,
	})
	if err == nil {
		t.Fatal("expected small-order rejection")
	}
}

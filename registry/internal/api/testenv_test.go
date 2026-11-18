package api_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/api"
	"github.com/Emmanue707/sealim/registry/internal/auth"
	"github.com/Emmanue707/sealim/registry/internal/store"
	"github.com/Emmanue707/sealim/registry/internal/trust"
)

type fixedClock struct {
	t time.Time
}

func (f fixedClock) Now() time.Time { return f.t.UTC() }

func testIssuerSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

func testIssuerBSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i + 0x21)
	}
	return s
}

func testRegistrySeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i + 0x41)
	}
	return s
}

func issuerKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

func testTrustJSON(t *testing.T, regPub ed25519.PublicKey) *trust.Store {
	t.Helper()
	issSeed := testIssuerSeed()
	sk := ed25519.NewKeyFromSeed(issSeed[:])
	pub := sk.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)
	pkB64 := base64.RawURLEncoding.EncodeToString(pub)

	bSeed := testIssuerBSeed()
	skB := ed25519.NewKeyFromSeed(bSeed[:])
	pubB := skB.Public().(ed25519.PublicKey)
	kidB := issuerKeyID(pubB)
	pkB64B := base64.RawURLEncoding.EncodeToString(pubB)

	regB64 := base64.RawURLEncoding.EncodeToString(regPub)
	regURL := "https://registry.example.invalid/v1"

	doc := map[string]interface{}{
		"format":     "sealim-trust",
		"version":    1,
		"updated_at": "2026-01-01T00:00:00Z",
		"issuers": []map[string]interface{}{
			{
				"name":                "University of Waghi",
				"key_id":              kid,
				"public_key":          pkB64,
				"valid_from":          "2020-01-01T00:00:00Z",
				"valid_until":         nil,
				"registry_url":        regURL,
				"registry_public_key": regB64,
			},
			{
				"name":        "University of Waghi",
				"key_id":      kidB,
				"public_key":  pkB64B,
				"valid_from":  "2020-01-01T00:00:00Z",
				"valid_until": nil,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := trust.LoadFile("test", raw)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func newTestServer(t *testing.T, clk time.Time) (*httptest.Server, ed25519.PrivateKey, ed25519.PrivateKey, *trust.Store) {
	t.Helper()
	rSeed := testRegistrySeed()
	regKey := ed25519.NewKeyFromSeed(rSeed[:])
	regPub := regKey.Public().(ed25519.PublicKey)
	tr := testTrustJSON(t, regPub)
	iSeed := testIssuerSeed()
	issuerKey := ed25519.NewKeyFromSeed(iSeed[:])

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := api.New(st, tr, regKey, fixedClock{t: clk})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, issuerKey, regKey, tr
}

func signPOST(t *testing.T, key ed25519.PrivateKey, path string, ts int64, body []byte) (string, string) {
	t.Helper()
	sig, err := auth.SignRequest(key, "POST", path, ts, body)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	return issuerKeyID(pub), sig
}

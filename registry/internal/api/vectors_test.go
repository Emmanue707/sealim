package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/auth"
)

type registryVector struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	Timestamp       int64  `json:"timestamp"`
	Body            string `json:"body"`
	PublicKeyB64URL string `json:"public_key_b64url"`
	SignatureB64URL string `json:"signature_b64url"`
	MessageHex      string `json:"message_hex"`
	KeyID           string `json:"key_id"`
}

func vectorPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	return filepath.Join(root, "testvectors", name)
}

func loadVector(t *testing.T, name string) registryVector {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(name))
	if err != nil {
		t.Fatal(err)
	}
	var v registryVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCrossLanguageRequestVectors(t *testing.T) {
	valid := loadVector(t, "registry_request_valid.json")
	body := []byte(valid.Body)
	msg := auth.RequestMessage(valid.Method, valid.Path, strconv.FormatInt(valid.Timestamp, 10), body)
	if hex.EncodeToString(msg) != valid.MessageHex {
		t.Fatal("message hex mismatch")
	}

	pkRaw, err := base64.RawURLEncoding.DecodeString(valid.PublicKeyB64URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(pkRaw)
	sig, err := auth.DecodeB64URLSig(valid.SignatureB64URL)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("valid vector signature failed verify")
	}

	clk := time.Unix(valid.Timestamp, 0).UTC()
	ts, _, _, _ := newTestServer(t, clk)
	req, err := http.NewRequest(http.MethodPost, ts.URL+valid.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sealim-Key-Id", valid.KeyID)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(valid.Timestamp, 10))
	req.Header.Set("Sealim-Signature", valid.SignatureB64URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("auth accept valid vector: %d", resp.StatusCode)
	}
	resp.Body.Close()

	bad := loadVector(t, "registry_request_bad_signature.json")
	body = []byte(bad.Body)
	msg = auth.RequestMessage(bad.Method, bad.Path, strconv.FormatInt(bad.Timestamp, 10), body)
	sig, err = auth.DecodeB64URLSig(bad.SignatureB64URL)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("bad vector should not verify")
	}
	req, err = http.NewRequest(http.MethodPost, ts.URL+bad.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sealim-Key-Id", bad.KeyID)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(bad.Timestamp, 10))
	req.Header.Set("Sealim-Signature", bad.SignatureB64URL)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad vector want 401 got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

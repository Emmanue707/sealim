package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/auth"
)

const (
	docID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	docHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestCORSHealthz(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, _, _, _ := newTestServer(t, clk)

	optReq, _ := http.NewRequest(http.MethodOptions, ts.URL+"/healthz", nil)
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil {
		t.Fatal(err)
	}
	optResp.Body.Close()
	if optResp.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS status %d", optResp.StatusCode)
	}
	if optResp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("OPTIONS ACAO %q", optResp.Header.Get("Access-Control-Allow-Origin"))
	}

	getResp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	getResp.Body.Close()
	if getResp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("GET ACAO %q", getResp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestHealthzAndIssuers(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, _, _, tr := newTestServer(t, clk)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}
	var h map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&h)
	if h["status"] != "ok" {
		t.Fatalf("health body %#v", h)
	}

	resp2, err := http.Get(ts.URL + "/v1/issuers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var issuers map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&issuers); err != nil {
		t.Fatal(err)
	}
	if issuers["format"] != "sealim-trust" || issuers["version"].(float64) != 1 {
		t.Fatalf("issuers shape %#v", issuers)
	}
	_ = tr
}

func TestRegisterRevokeRevocationList(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, issuerKey, regKey, tr := newTestServer(t, clk)
	pub := issuerKey.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)

	body, _ := json.Marshal(map[string]interface{}{
		"doc_id": docID, "doc_hash": docHash, "key_id": kid, "issued_at": 1735689600,
	})
	path := "/v1/documents"
	tsUnix := clk.Unix()
	kidHdr, sig := signPOST(t, issuerKey, path, tsUnix, body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(tsUnix, 10))
	req.Header.Set("Sealim-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register %d", resp.StatusCode)
	}

	getResp, err := http.Get(ts.URL + "/v1/documents/" + docID)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	var st map[string]interface{}
	_ = json.NewDecoder(getResp.Body).Decode(&st)
	if st["status"] != "valid" {
		t.Fatalf("get %#v", st)
	}

	revBody := []byte(`{"reason":"withdrawn"}`)
	revPath := "/v1/documents/" + docID + "/revoke"
	kidHdr, sig = signPOST(t, issuerKey, revPath, tsUnix, revBody)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+revPath, bytes.NewReader(revBody))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(tsUnix, 10))
	req.Header.Set("Sealim-Signature", sig)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("revoke %d", resp.StatusCode)
	}
	resp.Body.Close()

	revList, err := http.Get(ts.URL + "/v1/revocations")
	if err != nil {
		t.Fatal(err)
	}
	defer revList.Body.Close()
	raw, _ := io.ReadAll(revList.Body)
	sigHdr := revList.Header.Get("Sealim-Registry-Signature")
	if !verifyRevSig(regKey, raw, sigHdr) {
		t.Fatal("registry signature invalid")
	}
	var list struct {
		Entries []struct {
			DocID  string `json:"doc_id"`
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) != 1 || list.Entries[0].DocID != docID || list.Entries[0].Status != "revoked" {
		t.Fatalf("revocation list %#v", list)
	}
	bad := append([]byte(nil), raw...)
	if len(bad) > 10 {
		bad[10] ^= 0xff
		if verifyRevSig(regKey, bad, sigHdr) {
			t.Fatal("tampered body should fail signature")
		}
	}
	_ = tr
}

func verifyRevSig(regKey ed25519.PrivateKey, body []byte, sigHdr string) bool {
	msg := auth.RegistryRevMessage(body)
	sig, err := decodeSig(sigHdr)
	if err != nil {
		return false
	}
	pub := regKey.Public().(ed25519.PublicKey)
	return ed25519.Verify(pub, msg, sig)
}

func decodeSig(s string) ([]byte, error) {
	return auth.DecodeB64URLSig(s)
}

func TestSupersede(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, issuerKey, _, _ := newTestServer(t, clk)
	pub := issuerKey.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)
	replacement := "cccccccccccccccccccccccccccccccc"

	register(t, ts, issuerKey, kid, docID, docHash, clk.Unix())

	body, _ := json.Marshal(map[string]string{"superseded_by": replacement})
	path := "/v1/documents/" + docID + "/supersede"
	kidHdr, sig := signPOST(t, issuerKey, path, clk.Unix(), body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st["status"] != "superseded" || st["superseded_by"] != replacement {
		t.Fatalf("supersede %#v", st)
	}
}

func register(t *testing.T, ts *httptest.Server, key ed25519.PrivateKey, kid, docID, hash string, tsUnix int64) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"doc_id": docID, "doc_hash": hash, "key_id": kid, "issued_at": tsUnix,
	})
	path := "/v1/documents"
	kidHdr, sig := signPOST(t, key, path, tsUnix, body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(tsUnix, 10))
	req.Header.Set("Sealim-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestAuthFailures(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, issuerKey, _, _ := newTestServer(t, clk)
	pub := issuerKey.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)
	body, _ := json.Marshal(map[string]interface{}{
		"doc_id": docID, "doc_hash": docHash, "key_id": kid, "issued_at": 1735689600,
	})
	path := "/v1/documents"

	kidHdr, sig := signPOST(t, issuerKey, path, clk.Unix(), body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", "AAAA")
	if code := doStatus(req); code != http.StatusUnauthorized {
		t.Fatalf("bad sig want 401 got %d", code)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", "0000000000000000")
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusUnauthorized {
		t.Fatalf("unknown key want 401 got %d", code)
	}

	oldTs := clk.Unix() - 400
	kidHdr, sig = signPOST(t, issuerKey, path, oldTs, body)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(oldTs, 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusUnauthorized {
		t.Fatalf("stale ts want 401 got %d", code)
	}

	kidHdr, sig = signPOST(t, issuerKey, path, clk.Unix(), body)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("first register %d", code)
	}
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req2.Header.Set("Sealim-Key-Id", kidHdr)
	req2.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req2.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req2); code != http.StatusUnauthorized {
		t.Fatalf("replay want 401 got %d", code)
	}
}

func TestWrongIssuerRevoke(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, issuerKey, _, _ := newTestServer(t, clk)
	pub := issuerKey.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)
	register(t, ts, issuerKey, kid, docID, docHash, clk.Unix())

	bSeed := testIssuerBSeed()
	issuerB := ed25519.NewKeyFromSeed(bSeed[:])
	revBody := []byte(`{"reason":"other"}`)
	path := "/v1/documents/" + docID + "/revoke"
	kidHdr, sig := signPOST(t, issuerB, path, clk.Unix(), revBody)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(revBody))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusForbidden {
		t.Fatalf("wrong issuer want 403 got %d", code)
	}
}

func TestValidationAndIdempotency(t *testing.T) {
	clk := time.Unix(1735689600, 0).UTC()
	ts, issuerKey, _, _ := newTestServer(t, clk)
	pub := issuerKey.Public().(ed25519.PublicKey)
	kid := issuerKeyID(pub)

	shortBody, _ := json.Marshal(map[string]interface{}{
		"doc_id": "aaa", "doc_hash": docHash, "key_id": kid, "issued_at": 1735689600,
	})
	path := "/v1/documents"
	kidHdr, sig := signPOST(t, issuerKey, path, clk.Unix(), shortBody)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(shortBody))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusBadRequest {
		t.Fatalf("truncated hex want 400 got %d", code)
	}

	register(t, ts, issuerKey, kid, docID, docHash, clk.Unix())
	body, _ := json.Marshal(map[string]interface{}{
		"doc_id": docID, "doc_hash": docHash, "key_id": kid, "issued_at": 1735689600,
	})
	kidHdr, sig = signPOST(t, issuerKey, path, clk.Unix()+1, body)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix()+1, 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusOK {
		t.Fatalf("idempotent register want 200 got %d", code)
	}

	conflict, _ := json.Marshal(map[string]interface{}{
		"doc_id": docID, "doc_hash": strings.Repeat("c", 64), "key_id": kid, "issued_at": 1735689600,
	})
	kidHdr, sig = signPOST(t, issuerKey, path, clk.Unix()+1, conflict)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(conflict))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix()+1, 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusConflict {
		t.Fatalf("conflict want 409 got %d", code)
	}

	big := make([]byte, 17*1024)
	kidHdr, sig = signPOST(t, issuerKey, path, clk.Unix(), big)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(big))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized want 413 got %d", code)
	}

	revPath := "/v1/documents/" + docID + "/revoke"
	badReason := []byte(`{"reason":"lost"}`)
	kidHdr, sig = signPOST(t, issuerKey, revPath, clk.Unix(), badReason)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+revPath, bytes.NewReader(badReason))
	req.Header.Set("Sealim-Key-Id", kidHdr)
	req.Header.Set("Sealim-Timestamp", strconv.FormatInt(clk.Unix(), 10))
	req.Header.Set("Sealim-Signature", sig)
	if code := doStatus(req); code != http.StatusBadRequest {
		t.Fatalf("bad reason want 400 got %d", code)
	}
	_ = pub
}

func doStatus(req *http.Request) int {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

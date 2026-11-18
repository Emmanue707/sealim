package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestRequestMessageGolden(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	body := []byte(`{"doc_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","doc_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_id":"65b60673d6ed884b","issued_at":1735689600}`)
	sig, err := SignRequest(priv, "POST", "/v1/documents", 1735689600, body)
	if err != nil {
		t.Fatal(err)
	}
	want := "TuNoT_JMYwkGbxqDf-2fNwZuP8-4wt_eTLHbeqhOQ5fR_sDUjDtsBowFd_cexw5KIey1f8SBNedB5zXmmxXPBA"
	if sig != want {
		t.Fatalf("sig %q want %q", sig, want)
	}
	msg := RequestMessage("POST", "/v1/documents", "1735689600", body)
	wantMsg := hex.EncodeToString(RequestMessage("POST", "/v1/documents", "1735689600", body))
	if hex.EncodeToString(msg) != wantMsg {
		t.Fatalf("msg hex mismatch")
	}
}

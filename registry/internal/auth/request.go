package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/store"
	"github.com/Emmanue707/sealim/registry/internal/trust"
)

const maxSkew = 300 * time.Second

var ErrUnauthorized = errors.New("unauthorized")

type Verifier struct {
	Trust *trust.Store
	Store *store.Store
	Clock Clock
}

func RequestMessage(method, path, timestamp string, body []byte) []byte {
	h := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(h[:])
	var b strings.Builder
	b.Grow(len(method) + len(path) + len(timestamp) + 80)
	b.WriteString("SEALIM-REQ-v1\n")
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(timestamp)
	b.WriteByte('\n')
	b.WriteString(bodyHex)
	return []byte(b.String())
}

func decodeB64URL(sig string) ([]byte, error) {
	dec, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return base64.URLEncoding.DecodeString(sig)
	}
	return dec, nil
}

// DecodeB64URLSig decodes a base64url signature header value.
func DecodeB64URLSig(sig string) ([]byte, error) {
	return decodeB64URL(sig)
}

func (v *Verifier) Authenticate(r *http.Request, body []byte) (*trust.Issuer, error) {
	keyID := r.Header.Get("Sealim-Key-Id")
	tsHdr := r.Header.Get("Sealim-Timestamp")
	sigHdr := r.Header.Get("Sealim-Signature")
	if keyID == "" || tsHdr == "" || sigHdr == "" {
		return nil, ErrUnauthorized
	}

	iss, ok := v.Trust.Issuer(keyID)
	if !ok {
		return nil, ErrUnauthorized
	}
	now := v.Clock.Now()
	if !v.Trust.KeyValidNow(iss, now) {
		return nil, ErrUnauthorized
	}

	tsInt, err := strconv.ParseInt(tsHdr, 10, 64)
	if err != nil {
		return nil, ErrUnauthorized
	}
	reqTime := time.Unix(tsInt, 0).UTC()
	if d := now.Sub(reqTime); d < -maxSkew || d > maxSkew {
		return nil, ErrUnauthorized
	}

	sig, err := decodeB64URL(sigHdr)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrUnauthorized
	}

	path := r.URL.Path
	msg := RequestMessage(r.Method, path, tsHdr, body)
	if !ed25519.Verify(iss.PublicKey, msg, sig) {
		return nil, ErrUnauthorized
	}

	ctx := r.Context()
	replayKey := hex.EncodeToString(sig)
	inserted, err := v.Store.RememberSignature(ctx, replayKey, now.Unix())
	if err != nil {
		return nil, err
	}
	if !inserted {
		return nil, ErrUnauthorized
	}
	cutoff := now.Add(-maxSkew).Unix()
	_ = v.Store.PruneReplay(ctx, cutoff)

	return iss, nil
}

func SignRequest(priv ed25519.PrivateKey, method, path string, timestamp int64, body []byte) (string, error) {
	ts := strconv.FormatInt(timestamp, 10)
	msg := RequestMessage(method, path, ts, body)
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// MustMatchKeyID ensures body key_id matches authenticated issuer.
func MustMatchKeyID(bodyKeyID, authKeyID string) error {
	if strings.EqualFold(bodyKeyID, authKeyID) {
		return nil
	}
	return fmt.Errorf("key_id mismatch")
}

func IssuedAtReasonable(issuedAt int64, now time.Time) bool {
	if issuedAt < 946684800 { // 2000-01-01
		return false
	}
	if issuedAt > now.Unix()+300 {
		return false
	}
	return true
}

func RegistryRevMessage(body []byte) []byte {
	out := make([]byte, 0, len("SEALIM-REV-v1")+1+len(body))
	out = append(out, []byte("SEALIM-REV-v1")...)
	out = append(out, 0)
	out = append(out, body...)
	return out
}

func SignRegistryResponse(priv ed25519.PrivateKey, body []byte) string {
	msg := RegistryRevMessage(body)
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

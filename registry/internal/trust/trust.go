package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

var (
	ErrFormat           = errors.New("invalid trust file format")
	ErrVersion          = errors.New("unsupported trust version")
	ErrKeyID            = errors.New("key_id mismatch")
	ErrDuplicateKey     = errors.New("duplicate key_id")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrMissingRegistry  = errors.New("registry_url without registry_public_key")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
)

type Issuer struct {
	Name                 string
	KeyID                string
	PublicKey            ed25519.PublicKey
	PublicKeyB64         string
	ValidFrom            time.Time
	ValidUntil           *time.Time
	RegistryURL          *string
	RegistryPublicKey    ed25519.PublicKey
	RegistryPublicKeyB64 *string
}

type File struct {
	Format    string       `json:"format"`
	Version   int          `json:"version"`
	UpdatedAt string       `json:"updated_at"`
	Issuers   []IssuerJSON `json:"issuers"`
}

type IssuerJSON struct {
	Name              string  `json:"name"`
	KeyID             string  `json:"key_id"`
	PublicKey         string  `json:"public_key"`
	ValidFrom         string  `json:"valid_from"`
	ValidUntil        *string `json:"valid_until"`
	RegistryURL       *string `json:"registry_url"`
	RegistryPublicKey *string `json:"registry_public_key"`
}

type Store struct {
	UpdatedAt string
	byKeyID   map[string]*Issuer
}

func LoadFile(_ string, data []byte) (*Store, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, ErrFormat
	}
	if f.Format != "sealim-trust" {
		return nil, ErrFormat
	}
	if f.Version != 1 {
		return nil, ErrVersion
	}
	if f.UpdatedAt == "" {
		return nil, ErrFormat
	}

	store := &Store{
		UpdatedAt: f.UpdatedAt,
		byKeyID:   make(map[string]*Issuer),
	}

	for _, raw := range f.Issuers {
		iss, err := parseIssuer(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := store.byKeyID[iss.KeyID]; ok {
			return nil, ErrDuplicateKey
		}
		store.byKeyID[iss.KeyID] = iss
	}
	return store, nil
}

func parseIssuer(raw IssuerJSON) (*Issuer, error) {
	pk, pkB64, err := decodePublicKey(raw.PublicKey)
	if err != nil {
		return nil, err
	}
	computed := keyIDFromPublic(pk)
	declared := strings.ToLower(raw.KeyID)
	if computed != declared {
		return nil, ErrKeyID
	}
	validFrom, err := parseRFC3339(raw.ValidFrom)
	if err != nil {
		return nil, ErrInvalidTimestamp
	}
	var validUntil *time.Time
	if raw.ValidUntil != nil {
		t, err := parseRFC3339(*raw.ValidUntil)
		if err != nil {
			return nil, ErrInvalidTimestamp
		}
		validUntil = &t
	}

	iss := &Issuer{
		Name:         raw.Name,
		KeyID:        declared,
		PublicKey:    pk,
		PublicKeyB64: pkB64,
		ValidFrom:    validFrom,
		ValidUntil:   validUntil,
		RegistryURL:  raw.RegistryURL,
	}

	if raw.RegistryURL != nil {
		if raw.RegistryPublicKey == nil {
			return nil, ErrMissingRegistry
		}
		rpk, rb64, err := decodePublicKey(*raw.RegistryPublicKey)
		if err != nil {
			return nil, err
		}
		iss.RegistryPublicKey = rpk
		iss.RegistryPublicKeyB64 = &rb64
	} else if raw.RegistryPublicKey != nil {
		return nil, ErrMissingRegistry
	}
	return iss, nil
}

func decodePublicKey(b64 string) (ed25519.PublicKey, string, error) {
	dec, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		dec, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, "", ErrInvalidPublicKey
		}
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, "", ErrInvalidPublicKey
	}
	if rejectSmallOrder(dec) {
		return nil, "", ErrInvalidPublicKey
	}
	pk := ed25519.PublicKey(dec)
	canon := base64.RawURLEncoding.EncodeToString(pk)
	return pk, canon, nil
}

func keyIDFromPublic(pk ed25519.PublicKey) string {
	h := sha256.Sum256(pk)
	return hex.EncodeToString(h[:8])
}

func parseRFC3339(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func (s *Store) Issuer(keyID string) (*Issuer, bool) {
	iss, ok := s.byKeyID[strings.ToLower(keyID)]
	return iss, ok
}

func (s *Store) KeyValidNow(iss *Issuer, now time.Time) bool {
	if now.Before(iss.ValidFrom) {
		return false
	}
	if iss.ValidUntil != nil && !now.Before(*iss.ValidUntil) {
		return false
	}
	return true
}

func (s *Store) KeyValidAtIssue(iss *Issuer, issuedAt time.Time) bool {
	if issuedAt.Before(iss.ValidFrom) {
		return false
	}
	if iss.ValidUntil != nil && !issuedAt.Before(*iss.ValidUntil) {
		return false
	}
	return true
}

// PublicJSON returns the trust file shape for GET /v1/issuers.
func (s *Store) PublicJSON() File {
	out := File{
		Format:    "sealim-trust",
		Version:   1,
		UpdatedAt: s.UpdatedAt,
		Issuers:   make([]IssuerJSON, 0, len(s.byKeyID)),
	}
	for _, iss := range s.byKeyID {
		j := IssuerJSON{
			Name:        iss.Name,
			KeyID:       iss.KeyID,
			PublicKey:   iss.PublicKeyB64,
			ValidFrom:   iss.ValidFrom.UTC().Format(time.RFC3339),
			ValidUntil:  nil,
			RegistryURL: iss.RegistryURL,
		}
		if iss.ValidUntil != nil {
			v := iss.ValidUntil.UTC().Format(time.RFC3339)
			j.ValidUntil = &v
		}
		if iss.RegistryPublicKeyB64 != nil {
			j.RegistryPublicKey = iss.RegistryPublicKeyB64
		}
		out.Issuers = append(out.Issuers, j)
	}
	sort.Slice(out.Issuers, func(i, j int) bool {
		return out.Issuers[i].KeyID < out.Issuers[j].KeyID
	})
	return out
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/auth"
	"github.com/Emmanue707/sealim/registry/internal/hexutil"
	"github.com/Emmanue707/sealim/registry/internal/store"
	"github.com/Emmanue707/sealim/registry/internal/trust"
)

type registerRequest struct {
	DocID    string `json:"doc_id"`
	DocHash  string `json:"doc_hash"`
	KeyID    string `json:"key_id"`
	IssuedAt int64  `json:"issued_at"`
}

var allowedReasons = map[string]struct{}{
	"key_compromise":  {},
	"issued_in_error": {},
	"withdrawn":       {},
	"other":           {},
}

func (s *Server) handleRegister(w http.ResponseWriter, ctx context.Context, iss *trust.Issuer, req *registerRequest) error {
	if err := auth.MustMatchKeyID(req.KeyID, iss.KeyID); err != nil {
		return &statusError{http.StatusBadRequest, "key_id must match authenticated key"}
	}
	_, docLower, err := hexutil.DecodeFixedLower(req.DocID, 16)
	if err != nil {
		return &statusError{http.StatusBadRequest, "invalid doc_id"}
	}
	_, hashLower, err := hexutil.DecodeFixedLower(req.DocHash, 32)
	if err != nil {
		return &statusError{http.StatusBadRequest, "invalid doc_hash"}
	}
	keyLower := iss.KeyID
	now := s.Auth.Clock.Now()
	if !auth.IssuedAtReasonable(req.IssuedAt, now) {
		return &statusError{http.StatusBadRequest, "invalid issued_at"}
	}
	issueTime := time.Unix(req.IssuedAt, 0).UTC()
	if !s.Trust.KeyValidAtIssue(iss, issueTime) {
		return &statusError{http.StatusBadRequest, "issued_at outside key validity"}
	}

	existing, err := s.Store.GetDocument(ctx, docLower)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if existing != nil {
		if existing.DocHash == hashLower && existing.KeyID == keyLower && existing.IssuedAt == req.IssuedAt {
			statusJSON(w, http.StatusOK, existing)
			return nil
		}
		return &statusError{http.StatusConflict, "document exists with different fields"}
	}

	d := &store.Document{
		DocID:     docLower,
		DocHash:   hashLower,
		KeyID:     keyLower,
		IssuedAt:  req.IssuedAt,
		Status:    "valid",
		UpdatedAt: now,
	}
	if err := s.Store.InsertDocument(ctx, d); err != nil {
		return err
	}
	statusJSON(w, http.StatusCreated, d)
	return nil
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, ctx context.Context, iss *trust.Issuer, docID string, body []byte) {
	var req revokeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if _, ok := allowedReasons[req.Reason]; !ok {
		writeError(w, http.StatusBadRequest, "invalid reason")
		return
	}
	d, err := s.Store.GetDocument(ctx, docID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if d.KeyID != iss.KeyID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	now := s.Auth.Clock.Now()
	switch d.Status {
	case "valid":
		d.Status = "revoked"
		d.Reason = &req.Reason
		d.UpdatedAt = now
		if err := s.Store.UpdateDocument(ctx, d); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		statusJSON(w, http.StatusOK, d)
	case "revoked":
		if d.Reason != nil && *d.Reason == req.Reason {
			statusJSON(w, http.StatusOK, d)
			return
		}
		writeError(w, http.StatusConflict, "conflict")
	case "superseded":
		writeError(w, http.StatusConflict, "conflict")
	}
}

type supersedeRequest struct {
	SupersededBy string `json:"superseded_by"`
}

func (s *Server) handleSupersede(w http.ResponseWriter, ctx context.Context, iss *trust.Issuer, docID string, body []byte) {
	var req supersedeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	_, replLower, err := hexutil.DecodeFixedLower(req.SupersededBy, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid superseded_by")
		return
	}
	d, err := s.Store.GetDocument(ctx, docID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if d.KeyID != iss.KeyID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if other, err := s.Store.GetDocument(ctx, replLower); err == nil {
		if other.KeyID != d.KeyID {
			writeError(w, http.StatusBadRequest, "superseded_by key_id mismatch")
			return
		}
	}
	now := s.Auth.Clock.Now()
	switch d.Status {
	case "valid":
		d.Status = "superseded"
		d.Reason = nil
		d.SupersededBy = &replLower
		d.UpdatedAt = now
		if err := s.Store.UpdateDocument(ctx, d); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		statusJSON(w, http.StatusOK, d)
	case "superseded":
		if d.SupersededBy != nil && *d.SupersededBy == replLower {
			statusJSON(w, http.StatusOK, d)
			return
		}
		writeError(w, http.StatusConflict, "conflict")
	case "revoked":
		writeError(w, http.StatusConflict, "conflict")
	}
}

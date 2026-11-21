package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/auth"
	"github.com/Emmanue707/sealim/registry/internal/hexutil"
	"github.com/Emmanue707/sealim/registry/internal/store"
	"github.com/Emmanue707/sealim/registry/internal/trust"
)

const maxBody = 16 * 1024

type Server struct {
	Store       *store.Store
	Trust       *trust.Store
	RegistryKey ed25519.PrivateKey
	Auth        *auth.Verifier
}

func New(st *store.Store, tr *trust.Store, regKey ed25519.PrivateKey, clock auth.Clock) *Server {
	return &Server{
		Store:       st,
		Trust:       tr,
		RegistryKey: regKey,
		Auth: &auth.Verifier{
			Trust: tr,
			Store: st,
			Clock: clock,
		},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/v1/issuers", s.issuers)
	mux.HandleFunc("/v1/documents", s.documentsRoot)
	mux.HandleFunc("/v1/revocations", s.revocations)
	mux.HandleFunc("/v1/documents/", s.documentsSub)
	return withCORS(mux)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) issuers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.Trust.PublicJSON())
}

func (s *Server) documentsRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		return
	}
	iss, err := s.Auth.Authenticate(r, body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.handleRegister(w, r.Context(), iss, &req); err != nil {
		var apiErr *statusError
		if errors.As(err, &apiErr) {
			writeError(w, apiErr.code, apiErr.msg)
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
	}
}

func (s *Server) documentsSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/documents/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	docHex := parts[0]
	_, docID, err := hexutil.DecodeFixedLower(docHex, 16)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid doc_id")
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.getDocument(w, r.Context(), docID)
		return
	}

	action := parts[1]
	switch action {
	case "revoke":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			return
		}
		iss, err := s.Auth.Authenticate(r, body)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.handleRevoke(w, r.Context(), iss, docID, body)
	case "supersede":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			return
		}
		iss, err := s.Auth.Authenticate(r, body)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.handleSupersede(w, r.Context(), iss, docID, body)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return nil, err
		}
		writeError(w, http.StatusBadRequest, "invalid body")
		return nil, err
	}
	return body, nil
}

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

func statusJSON(w http.ResponseWriter, code int, d *store.Document) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(documentStatus(d))
}

type documentStatusJSON struct {
	DocID        string  `json:"doc_id"`
	Status       string  `json:"status"`
	Reason       *string `json:"reason"`
	SupersededBy *string `json:"superseded_by"`
	UpdatedAt    string  `json:"updated_at"`
}

func documentStatus(d *store.Document) documentStatusJSON {
	return documentStatusJSON{
		DocID:        d.DocID,
		Status:       d.Status,
		Reason:       d.Reason,
		SupersededBy: d.SupersededBy,
		UpdatedAt:    d.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func (s *Server) getDocument(w http.ResponseWriter, ctx context.Context, docID string) {
	d, err := s.Store.GetDocument(ctx, docID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	statusJSON(w, http.StatusOK, d)
}

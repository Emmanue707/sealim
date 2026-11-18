package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Emmanue707/sealim/registry/internal/auth"
)

type revListBody struct {
	UpdatedAt string        `json:"updated_at"`
	Entries   []revListItem `json:"entries"`
}

type revListItem struct {
	DocID        string  `json:"doc_id"`
	Status       string  `json:"status"`
	Reason       *string `json:"reason"`
	SupersededBy *string `json:"superseded_by"`
	UpdatedAt    string  `json:"updated_at"`
}

func (s *Server) revocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var since *time.Time
	if q := r.URL.Query().Get("since"); q != "" {
		t, err := time.Parse(time.RFC3339, q)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since")
			return
		}
		u := t.UTC()
		since = &u
	}
	rows, err := s.Store.ListNonValidSince(r.Context(), since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := s.Auth.Clock.Now().UTC()
	entries := make([]revListItem, 0, len(rows))
	for i := range rows {
		entries = append(entries, revListItem{
			DocID:        rows[i].DocID,
			Status:       rows[i].Status,
			Reason:       rows[i].Reason,
			SupersededBy: rows[i].SupersededBy,
			UpdatedAt:    rows[i].UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	body := revListBody{
		UpdatedAt: now.Format(time.RFC3339),
		Entries:   entries,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	sig := auth.SignRegistryResponse(s.RegistryKey, out)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Sealim-Registry-Signature", sig)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

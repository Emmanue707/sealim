package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Emmanue707/sealim/registry/migrations"

	_ "modernc.org/sqlite"
)

type Document struct {
	DocID        string
	DocHash      string
	KeyID        string
	IssuedAt     int64
	Status       string
	Reason       *string
	SupersededBy *string
	UpdatedAt    time.Time
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(string(data)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

var ErrNotFound = errors.New("not found")

func (s *Store) GetDocument(ctx context.Context, docID string) (*Document, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT doc_id, doc_hash, key_id, issued_at, status, reason, superseded_by, updated_at
		FROM documents WHERE doc_id = ?`, docID)
	return scanDoc(row)
}

func scanDoc(row *sql.Row) (*Document, error) {
	var d Document
	var updated string
	var reason, superseded sql.NullString
	err := row.Scan(&d.DocID, &d.DocHash, &d.KeyID, &d.IssuedAt, &d.Status, &reason, &superseded, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if reason.Valid {
		d.Reason = &reason.String
	}
	if superseded.Valid {
		d.SupersededBy = &superseded.String
	}
	t, err := time.Parse(time.RFC3339, updated)
	if err != nil {
		return nil, err
	}
	d.UpdatedAt = t.UTC()
	return &d, nil
}

func (s *Store) InsertDocument(ctx context.Context, d *Document) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO documents (doc_id, doc_hash, key_id, issued_at, status, reason, superseded_by, updated_at)
		VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)`,
		d.DocID, d.DocHash, d.KeyID, d.IssuedAt, d.Status, d.UpdatedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) UpdateDocument(ctx context.Context, d *Document) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE documents SET status = ?, reason = ?, superseded_by = ?, updated_at = ?
		WHERE doc_id = ?`,
		d.Status, nullStr(d.Reason), nullStr(d.SupersededBy), d.UpdatedAt.UTC().Format(time.RFC3339), d.DocID)
	return err
}

func nullStr(p *string) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

func (s *Store) ListNonValidSince(ctx context.Context, since *time.Time) ([]Document, error) {
	var rows *sql.Rows
	var err error
	if since == nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT doc_id, doc_hash, key_id, issued_at, status, reason, superseded_by, updated_at
			FROM documents WHERE status != 'valid' ORDER BY updated_at ASC`)
	} else {
		sinceStr := since.UTC().Format(time.RFC3339)
		rows, err = s.db.QueryContext(ctx, `
			SELECT doc_id, doc_hash, key_id, issued_at, status, reason, superseded_by, updated_at
			FROM documents WHERE status != 'valid' AND updated_at >= ? ORDER BY updated_at ASC`, sinceStr)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Document
	for rows.Next() {
		var d Document
		var updated string
		var reason, superseded sql.NullString
		if err := rows.Scan(&d.DocID, &d.DocHash, &d.KeyID, &d.IssuedAt, &d.Status, &reason, &superseded, &updated); err != nil {
			return nil, err
		}
		if reason.Valid {
			d.Reason = &reason.String
		}
		if superseded.Valid {
			d.SupersededBy = &superseded.String
		}
		t, err := time.Parse(time.RFC3339, updated)
		if err != nil {
			return nil, err
		}
		d.UpdatedAt = t.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// RememberSignature records a signature. inserted is false if it was already present.
func (s *Store) RememberSignature(ctx context.Context, sigKey string, seenAt int64) (inserted bool, err error) {
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO auth_replay (sig_key, seen_at) VALUES (?, ?)`, sigKey, seenAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) PruneReplay(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_replay WHERE seen_at < ?`, before)
	return err
}

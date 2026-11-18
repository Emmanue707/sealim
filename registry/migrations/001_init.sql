CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY,
    doc_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('valid', 'revoked', 'superseded')),
    reason TEXT,
    superseded_by TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_replay (
    sig_key TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_documents_updated ON documents(updated_at);
CREATE INDEX IF NOT EXISTS idx_auth_replay_seen ON auth_replay(seen_at);
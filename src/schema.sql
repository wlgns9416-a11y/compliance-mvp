-- Milestone 2 schema.
-- Written against Postgres semantics so the same DDL moves to Supabase with
-- only the type names changed (INTEGER PRIMARY KEY -> BIGSERIAL, TEXT -> TEXT).
--
-- Design note. The unit of work is the CHUNK, not the document. Every retry
-- decision, every state transition and every uniqueness constraint is anchored
-- at chunk level, which is what makes "retry the failed part without
-- reprocessing the whole document" fall out of the schema rather than out of
-- application logic.

CREATE TABLE IF NOT EXISTS documents (
  id           INTEGER PRIMARY KEY,
  org_id       TEXT    NOT NULL,              -- multi-tenant boundary (see M1 section)
  filename     TEXT    NOT NULL,
  content_hash TEXT    NOT NULL,              -- idempotent re-upload detection
  page_count   INTEGER NOT NULL DEFAULT 0,
  status       TEXT    NOT NULL DEFAULT 'uploaded',
                                              -- uploaded|extracted|chunked|analyzing|complete|failed
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (org_id, content_hash)
);

CREATE TABLE IF NOT EXISTS chunks (
  id          INTEGER PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  seq         INTEGER NOT NULL,               -- 0-based order within document
  page_start  INTEGER NOT NULL,               -- 1-based, inclusive
  page_end    INTEGER NOT NULL,               -- 1-based, inclusive
  text        TEXT    NOT NULL,
  text_hash   TEXT    NOT NULL,               -- content identity, survives re-chunking
  status      TEXT    NOT NULL DEFAULT 'pending',
                                              -- pending|processing|done|failed|dead
  attempts    INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT,
  leased_until TEXT,                          -- crash recovery: expired lease = reclaimable
  next_attempt_at TEXT,                       -- exponential backoff gate
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE (document_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_chunks_claimable
  ON chunks(document_id, status, leased_until);

CREATE TABLE IF NOT EXISTS findings (
  id           INTEGER PRIMARY KEY,
  document_id  INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  chunk_id     INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
  rule_id      TEXT    NOT NULL,
  severity     TEXT    NOT NULL,              -- critical|warning|informational
  message      TEXT    NOT NULL,
  page_ref     INTEGER NOT NULL,              -- 1-based page the finding points at
  excerpt      TEXT,
  state        TEXT    NOT NULL DEFAULT 'open',   -- open|resolved|ignored
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  -- THE idempotency guarantee: re-analysing a chunk cannot duplicate findings.
  -- Anchored on text_hash-derived rule identity, so a retry that produces the
  -- same finding is a no-op rather than a second row.
  UNIQUE (chunk_id, rule_id, page_ref)
);

CREATE INDEX IF NOT EXISTS idx_findings_doc_state
  ON findings(document_id, state, severity);

-- Rules are data, not code. Adding a compliance checklist is an INSERT.
CREATE TABLE IF NOT EXISTS rules (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  title       TEXT NOT NULL,
  severity    TEXT NOT NULL,
  pattern     TEXT NOT NULL,                  -- what the analyser looks for
  enabled     INTEGER NOT NULL DEFAULT 1
);

-- One row per pipeline invocation. Lets the UI show "resumed run" vs "first run"
-- and gives an audit trail of how many attempts a document actually took.
CREATE TABLE IF NOT EXISTS runs (
  id           INTEGER PRIMARY KEY,
  document_id  INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  started_at   TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at  TEXT,
  chunks_total INTEGER NOT NULL DEFAULT 0,
  chunks_done  INTEGER NOT NULL DEFAULT 0,
  chunks_failed INTEGER NOT NULL DEFAULT 0,
  outcome      TEXT                            -- complete|partial|failed
);

-- ---------------------------------------------------------------- M1: tenancy
-- Identity lives in the auth provider (Supabase Auth / Google OIDC). This table
-- is the local projection of it — never a password store. `auth_subject` is the
-- provider's stable user id, which is what survives an email change.

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY,
  auth_subject TEXT NOT NULL UNIQUE,
  email        TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS organizations (
  id         INTEGER PRIMARY KEY,
  slug       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Membership is the join, and it is also the authorization record. A user with
-- no row here for an org has no path to that org's data — there is no "global
-- admin" bypass, deliberately.
CREATE TABLE IF NOT EXISTS memberships (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role       TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, org_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(org_id, role);

-- Usage is metered per org per period. Enforcement reads this row inside the
-- same transaction that creates the document, so two concurrent uploads cannot
-- both pass a limit that only one of them fits under.
CREATE TABLE IF NOT EXISTS usage_counters (
  org_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  period     TEXT NOT NULL,                  -- 'YYYY-MM'
  documents  INTEGER NOT NULL DEFAULT 0,
  doc_limit  INTEGER NOT NULL DEFAULT 50,
  PRIMARY KEY (org_id, period)
);

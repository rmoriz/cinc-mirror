-- Ledger schema, version 1.
--
-- `events` is the append-only log and the only source of truth. Every other
-- table is derived from it and is rebuilt by `Ledger::materialize`, so no
-- derived table may hold data that an event cannot reconstruct.
--
-- The shape follows the design document. Two additions are deliberate:
--
-- * `schema_version` is created by the migration runner in `mod.rs`, not here.
-- * `artifacts.local` records whether the verified blob is still in the local
--   store. `verified` sets it and `local_gc` clears it; without it a deep
--   verification cannot distinguish "deleted after publishing" from
--   "corrupt".

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    artifact_key TEXT,
    target TEXT,
    detail_json TEXT NOT NULL,
    UNIQUE (run_id, seq)
);

CREATE INDEX IF NOT EXISTS events_order ON events (ts, run_id, seq);
CREATE INDEX IF NOT EXISTS events_artifact ON events (artifact_key, target);

CREATE TABLE IF NOT EXISTS artifacts (
    key TEXT PRIMARY KEY,
    upstream_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER,
    basename TEXT NOT NULL,
    project TEXT NOT NULL,
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    iteration TEXT,
    platform TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    arch TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT 'null',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    superseded_by TEXT,
    supersedes TEXT,
    local INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS artifacts_upstream_path ON artifacts (upstream_path);
CREATE INDEX IF NOT EXISTS artifacts_order
    ON artifacts (version, project, platform, platform_version, arch, basename);

CREATE TABLE IF NOT EXISTS publications (
    artifact_key TEXT NOT NULL REFERENCES artifacts (key) ON DELETE CASCADE,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    remote_ref TEXT,
    remote_digest TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (artifact_key, target)
);

CREATE INDEX IF NOT EXISTS publications_target_status
    ON publications (target, status);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    artifact_key TEXT REFERENCES artifacts (key) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    old_sha256 TEXT,
    new_sha256 TEXT,
    detected_at TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT 'null',
    state TEXT NOT NULL,
    issue_url TEXT,
    ack_note TEXT
);

-- One open incident per changed hash pair; acked incidents do not block a
-- later, genuinely new detection.
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_detection
    ON incidents (artifact_key, old_sha256, new_sha256)
    WHERE state = 'open';

CREATE INDEX IF NOT EXISTS incidents_state ON incidents (state, detected_at);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    effective_policy TEXT NOT NULL DEFAULT 'null',
    "order" TEXT,
    max_bytes INTEGER,
    transport_order TEXT NOT NULL DEFAULT '[]',
    host TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    outcome TEXT,
    summary_json TEXT NOT NULL DEFAULT 'null',
    leased INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cursors (
    fingerprint TEXT PRIMARY KEY,
    last_version TEXT,
    last_artifact_key TEXT,
    updated_at TEXT NOT NULL
);

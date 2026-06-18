-- Git Warden ingestion store (Week 1).
--
-- Two layers, mirroring models.py:
--   * source_observations -- append-only audit layer. One row per (feed, actor,
--     run) claim. Never updated, never deleted (PRD 11, "Retain everything").
--   * threat_actors + actor_identifiers + campaigns -- normalized entities that
--     observations roll up into via the validator.
--
-- The actor_sources table is the corroboration ledger: distinct feeds per
-- actor. COUNT(*) over it drives promotion (>= 2 -> promoted).
--
-- SQLite is version-controlled and single-file (PRD 9). Foreign keys are OFF by
-- default in SQLite; database.py enables them per-connection.

PRAGMA foreign_keys = ON;

--- books
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TEXT NOT NULL,           -- ISO-8601 UTC
    finished_at     TEXT,
    config_snapshot TEXT NOT NULL DEFAULT '{}',  -- JSON
    counts          TEXT NOT NULL DEFAULT '{}',  -- JSON
    notes           TEXT
);

-- ---------------------------------------------------------------------------
-- Raw audit layer: append-only
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_observations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL REFERENCES runs(run_id),
    source           TEXT NOT NULL,
    observed_at      TEXT NOT NULL,
    actor_key        TEXT NOT NULL,          -- normalized dedup key
    actor_name       TEXT NOT NULL,          -- as seen in the feed
    source_record_id TEXT,
    url              TEXT,
    category         TEXT NOT NULL DEFAULT 'unknown',
    identifiers      TEXT NOT NULL DEFAULT '[]',  -- JSON
    campaigns        TEXT NOT NULL DEFAULT '[]',  -- JSON
    raw_payload      TEXT NOT NULL DEFAULT '{}'   -- JSON, verbatim feed payload
);

CREATE INDEX IF NOT EXISTS idx_obs_actor_key ON source_observations(actor_key);
CREATE INDEX IF NOT EXISTS idx_obs_run ON source_observations(run_id);
CREATE INDEX IF NOT EXISTS idx_obs_source ON source_observations(source);

-- ---------------------------------------------------------------------------
-- Normalized entities
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_actors (
    actor_key      TEXT PRIMARY KEY,         -- normalized name
    canonical_name TEXT NOT NULL,            -- chosen display name
    category       TEXT NOT NULL DEFAULT 'unknown',
    status         TEXT NOT NULL DEFAULT 'candidate',
    first_seen_run TEXT REFERENCES runs(run_id),
    last_seen_run  TEXT REFERENCES runs(run_id),
    notes          TEXT
);

CREATE INDEX IF NOT EXISTS idx_actor_status ON threat_actors(status);

-- Corroboration ledger: distinct feeds that have observed each actor.
-- The (actor_key, source) uniqueness is what makes corroboration count
-- *independent* feeds rather than repeated sightings from the same feed.
CREATE TABLE IF NOT EXISTS actor_sources (
    actor_key            TEXT NOT NULL REFERENCES threat_actors(actor_key) ON DELETE CASCADE,
    source               TEXT NOT NULL,
    first_observation_id INTEGER REFERENCES source_observations(id),
    observation_count    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (actor_key, source)
);

CREATE TABLE IF NOT EXISTS actor_identifiers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_key       TEXT NOT NULL REFERENCES threat_actors(actor_key) ON DELETE CASCADE,
    identifier_type TEXT NOT NULL,
    value           TEXT NOT NULL,
    platform        TEXT NOT NULL DEFAULT 'generic',
    UNIQUE (actor_key, identifier_type, value, platform)
);

CREATE INDEX IF NOT EXISTS idx_ident_actor ON actor_identifiers(actor_key);
CREATE INDEX IF NOT EXISTS idx_ident_value ON actor_identifiers(value);

CREATE TABLE IF NOT EXISTS campaigns (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL UNIQUE,
    targets TEXT NOT NULL DEFAULT '[]'        -- JSON
);

CREATE TABLE IF NOT EXISTS actor_campaigns (
    actor_key   TEXT NOT NULL REFERENCES threat_actors(actor_key) ON DELETE CASCADE,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    PRIMARY KEY (actor_key, campaign_id)
);

-- ---------------------------------------------------------------------------
-- Malicious artifacts: known-bad packages/repos (OSM) and the Week-2 scan list
-- ---------------------------------------------------------------------------
-- The bridge from ingestion to the GitHub scanning layer. OSM populates this
-- with already-labeled artifacts; actor_key links to a threat actor when the
-- source attributes one (nullable for unattributed indicators).
CREATE TABLE IF NOT EXISTS malicious_artifacts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type  TEXT NOT NULL,            -- 'package' | 'repo'
    ecosystem      TEXT NOT NULL DEFAULT 'unknown',  -- npm, pypi, github, ...
    name           TEXT NOT NULL,
    url            TEXT,
    source         TEXT NOT NULL,
    actor_key      TEXT REFERENCES threat_actors(actor_key) ON DELETE SET NULL,
    status         TEXT NOT NULL DEFAULT 'labeled',
    first_seen_run TEXT REFERENCES runs(run_id),
    last_seen_run  TEXT REFERENCES runs(run_id),
    raw_payload    TEXT NOT NULL DEFAULT '{}',
    UNIQUE (artifact_type, ecosystem, name)
);

CREATE INDEX IF NOT EXISTS idx_artifact_actor ON malicious_artifacts(actor_key);
CREATE INDEX IF NOT EXISTS idx_artifact_name ON malicious_artifacts(name);
CREATE INDEX IF NOT EXISTS idx_artifact_status ON malicious_artifacts(status);

-- ---------------------------------------------------------------------------
-- Malicious-repo registry: THE PRODUCT
-- ---------------------------------------------------------------------------
-- Unified registry of malicious (and candidate) GitHub repositories with the
-- reasoning, attribution, detection signals and provenance breadcrumbs that
-- surfaced them. Confirmed rows feed the Discord gold output (doc 02 section 6).
CREATE TABLE IF NOT EXISTS repo_findings (
    full_name        TEXT PRIMARY KEY,        -- owner/repo, normalized lowercase
    url              TEXT,
    detection_method TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'candidate',
    score            INTEGER NOT NULL DEFAULT 0,
    actor_key        TEXT REFERENCES threat_actors(actor_key) ON DELETE SET NULL,
    reasoning        TEXT,
    signals          TEXT NOT NULL DEFAULT '[]',   -- JSON
    matched_iocs     TEXT NOT NULL DEFAULT '[]',   -- JSON
    first_seen_run   TEXT REFERENCES runs(run_id),
    last_seen_run    TEXT REFERENCES runs(run_id),
    raw_payload      TEXT NOT NULL DEFAULT '{}',
    delivered_gold   INTEGER NOT NULL DEFAULT 0    -- 1 once sent to Discord
);

CREATE INDEX IF NOT EXISTS idx_finding_status ON repo_findings(status);
CREATE INDEX IF NOT EXISTS idx_finding_method ON repo_findings(detection_method);
CREATE INDEX IF NOT EXISTS idx_finding_actor ON repo_findings(actor_key);

-- ---------------------------------------------------------------------------
-- Learned IOCs: the compounding loop (expand core search)
-- ---------------------------------------------------------------------------
-- IOCs mined from the code of CONFIRMED malicious repos. Future hunts mirror
-- these into GitHub code search alongside OSM's IOCs, so each confirmation
-- widens the net.
CREATE TABLE IF NOT EXISTS learned_iocs (
    value          TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,          -- webhook | telegram | domain
    source_repo    TEXT,
    first_seen_run TEXT REFERENCES runs(run_id)
);

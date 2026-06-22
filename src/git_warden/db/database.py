"""SQLite connection management and the ingestion repository.

Stdlib ``sqlite3`` only; no ORM (PRD section 9: SQLite, no external database
in phase 1). The :class:`Database` class exposes the small set of operations the
ingestion layer needs:

* record a run and finalize it with counts,
* persist a :class:`~git_warden.models.SourceObservation` to the append-only
  audit layer,
* upsert the normalized actor it rolls up into, tracking which independent
  feeds corroborate it.

Promotion logic (candidate -> quarantined/promoted) lives in the validator,
which reads from here; this module only persists facts.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ..config import DB_PATH
from ..enums import RunStatus
from ..models import (
    ActorIdentifier,
    Campaign,
    MaliciousArtifact,
    RepoFinding,
    SourceObservation,
    ThreatActor,
)

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    """Open a connection with foreign keys enforced and row access by name."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    """Lightweight forward-only migration: add any missing columns."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db(conn: sqlite3.Connection) -> None:
    """Create all tables from schema.sql. Idempotent (uses IF NOT EXISTS).

    Also runs forward-only column migrations so an older store gains new columns
    (e.g. cross-platform fields) without a rebuild.
    """
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _ensure_columns(conn, "repo_findings", {
        "platform": "TEXT NOT NULL DEFAULT 'github'",
        "code_hash": "TEXT",
    })
    # Created here (not in schema.sql) so it works on an upgraded store, where
    # code_hash is added by the migration above rather than CREATE TABLE.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_code_hash ON repo_findings(code_hash)"
    )
    conn.commit()


class Database:
    """Thin repository over a single SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    #; lifecycle ---------------------------------------------------------
    @classmethod
    def open(cls, db_path: Path | str = DB_PATH) -> Database:
        conn = connect(db_path)
        init_db(conn)
        return cls(conn)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Atomic unit of work; commit on success, roll back on error."""
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    #; runs --------------------------------------------------------------
    def start_run(self, run_id: str, started_at: datetime, config: dict | None = None) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO runs (run_id, status, started_at, config_snapshot) "
                "VALUES (?, ?, ?, ?)",
                (run_id, RunStatus.RUNNING.value, started_at.isoformat(),
                 json.dumps(config or {})),
            )

    def finish_run(
        self,
        run_id: str,
        finished_at: datetime,
        status: RunStatus,
        counts: dict[str, int] | None = None,
    ) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE runs SET status = ?, finished_at = ?, counts = ? WHERE run_id = ?",
                (status.value, finished_at.isoformat(), json.dumps(counts or {}), run_id),
            )

    #; raw observations (append-only) ------------------------------------
    def record_observation(self, obs: SourceObservation) -> int:
        """Insert one raw observation. Returns its row id. Never updates."""
        with self.transaction() as c:
            cur = c.execute(
                """
                INSERT INTO source_observations
                    (run_id, source, observed_at, actor_key, actor_name,
                     source_record_id, url, category, identifiers, campaigns, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs.run_id,
                    obs.source.value,
                    obs.observed_at.isoformat(),
                    obs.actor_key,
                    obs.actor_name,
                    obs.source_record_id,
                    str(obs.url) if obs.url else None,
                    obs.category.value,
                    json.dumps([i.model_dump() for i in obs.identifiers]),
                    json.dumps([cmp.model_dump() for cmp in obs.campaigns]),
                    json.dumps(obs.raw_payload, default=str),
                ),
            )
            return int(cur.lastrowid)

    #; normalized actors -------------------------------------------------
    def upsert_actor(self, actor: ThreatActor) -> None:
        """Create or update the normalized actor row (excluding corroboration).

        Corroboration is tracked via :meth:`link_actor_source`; identifiers and
        campaigns via their own helpers. This keeps each fact additive and the
        operation idempotent across re-runs.
        """
        with self.transaction() as c:
            c.execute(
                """
                INSERT INTO threat_actors
                    (actor_key, canonical_name, category, status, first_seen_run,
                     last_seen_run, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(actor_key) DO UPDATE SET
                    canonical_name = excluded.canonical_name,
                    category = excluded.category,
                    status = excluded.status,
                    last_seen_run = excluded.last_seen_run,
                    notes = excluded.notes
                """,
                (
                    actor.actor_key,
                    actor.canonical_name,
                    actor.category.value,
                    actor.status.value,
                    actor.first_seen_run,
                    actor.last_seen_run,
                    actor.notes,
                ),
            )

    def ensure_actor(
        self,
        actor_key: str,
        canonical_name: str,
        category: str,
        run_id: str,
    ) -> None:
        """Create the actor on first sighting; otherwise only bump last_seen_run.

        Unlike :meth:`upsert_actor`, this never clobbers an existing actor's
        status or category; the validator owns status, and the first feed to
        name an actor sets its canonical name. This keeps re-runs idempotent.
        """
        with self.transaction() as c:
            c.execute(
                """
                INSERT INTO threat_actors
                    (actor_key, canonical_name, category, status, first_seen_run, last_seen_run)
                VALUES (?, ?, ?, 'candidate', ?, ?)
                ON CONFLICT(actor_key) DO UPDATE SET last_seen_run = excluded.last_seen_run
                """,
                (actor_key, canonical_name, category, run_id, run_id),
            )

    def set_actor_status(self, actor_key: str, status: str) -> None:
        """Update only an actor's status (the validator's single write)."""
        with self.transaction() as c:
            c.execute(
                "UPDATE threat_actors SET status = ? WHERE actor_key = ?",
                (status, actor_key),
            )

    def link_actor_source(self, actor_key: str, source: str, observation_id: int) -> None:
        """Record that ``source`` corroborates ``actor_key``.

        Inserts on first sighting from this feed, bumps the count on repeats.
        Distinct rows here == independent feeds, which is what corroboration
        counts.
        """
        with self.transaction() as c:
            c.execute(
                """
                INSERT INTO actor_sources (actor_key, source, first_observation_id)
                VALUES (?, ?, ?)
                ON CONFLICT(actor_key, source) DO UPDATE SET
                    observation_count = observation_count + 1
                """,
                (actor_key, source, observation_id),
            )

    def add_identifier(self, actor_key: str, identifier: ActorIdentifier) -> None:
        with self.transaction() as c:
            c.execute(
                """
                INSERT OR IGNORE INTO actor_identifiers
                    (actor_key, identifier_type, value, platform)
                VALUES (?, ?, ?, ?)
                """,
                (actor_key, identifier.identifier_type.value, identifier.value,
                 identifier.platform.value),
            )

    def add_campaign(self, actor_key: str, campaign: Campaign) -> None:
        with self.transaction() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO campaigns (name, targets) VALUES (?, ?)",
                (campaign.name, json.dumps(campaign.targets)),
            )
            row = c.execute("SELECT id FROM campaigns WHERE name = ?", (campaign.name,)).fetchone()
            campaign_id = row["id"]
            c.execute(
                "INSERT OR IGNORE INTO actor_campaigns (actor_key, campaign_id) VALUES (?, ?)",
                (actor_key, campaign_id),
            )
            _ = cur  # silence unused; insert side effect is the point

    #; queries -----------------------------------------------------------
    def corroborating_source_count(self, actor_key: str) -> int:
        """Number of distinct feeds that have observed this actor."""
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM actor_sources WHERE actor_key = ?", (actor_key,)
        ).fetchone()
        return int(row["n"])

    def get_actor(self, actor_key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM threat_actors WHERE actor_key = ?", (actor_key,)
        ).fetchone()

    #; malicious artifacts (OSM / Week-2 scan list) ----------------------
    def upsert_artifact(self, artifact: MaliciousArtifact, run_id: str) -> int:
        """Insert or refresh a labeled artifact; returns its row id.

        Deduplicates on (type, ecosystem, name). On conflict it bumps
        last_seen_run and fills in an actor_key if one became known, but never
        downgrades a manually CONFIRMED/REJECTED status back to LABELED.
        """
        with self.transaction() as c:
            c.execute(
                """
                INSERT INTO malicious_artifacts
                    (artifact_type, ecosystem, name, url, source, actor_key,
                     status, first_seen_run, last_seen_run, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(artifact_type, ecosystem, name) DO UPDATE SET
                    last_seen_run = excluded.last_seen_run,
                    url = COALESCE(excluded.url, malicious_artifacts.url),
                    actor_key = COALESCE(malicious_artifacts.actor_key, excluded.actor_key)
                """,
                (
                    artifact.artifact_type.value,
                    artifact.ecosystem,
                    artifact.name,
                    str(artifact.url) if artifact.url else None,
                    artifact.source.value,
                    artifact.actor_key,
                    artifact.status.value,
                    run_id,
                    run_id,
                    json.dumps(artifact.raw_payload, default=str),
                ),
            )
            row = c.execute(
                "SELECT id FROM malicious_artifacts "
                "WHERE artifact_type = ? AND ecosystem = ? AND name = ?",
                (artifact.artifact_type.value, artifact.ecosystem, artifact.name),
            ).fetchone()
            return int(row["id"])

    def list_artifacts(
        self, artifact_type: str | None = None, limit: int | None = None
    ) -> list[sqlite3.Row]:
        """List malicious artifacts, optionally filtered by type (the scan list)."""
        sql = "SELECT * FROM malicious_artifacts"
        params: list = []
        if artifact_type:
            sql += " WHERE artifact_type = ?"
            params.append(artifact_type)
        sql += " ORDER BY id"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return self.conn.execute(sql, params).fetchall()

    #; malicious-repo registry (the product) -----------------------------
    def upsert_finding(self, finding: RepoFinding, run_id: str) -> None:
        """Insert or refresh a repo finding. Dedups on full_name.

        On conflict: refresh score/status/reasoning/signals and last_seen_run,
        but never revive a manually REJECTED finding and never clear an existing
        actor attribution. Re-run safe.
        """
        with self.transaction() as c:
            # actor_key is a strict FK to threat_actors. An EXTERNAL attribution
            # label (e.g. OSM's "DPRK (North Korea) (per OSM)") is not a registered
            # actor, so coerce an unknown key to NULL rather than crash the whole
            # run on a FOREIGN KEY violation. The human-readable attribution is
            # preserved in the finding's reasoning.
            actor_key = finding.actor_key
            if actor_key and not c.execute(
                "SELECT 1 FROM threat_actors WHERE actor_key = ?", (actor_key,)
            ).fetchone():
                actor_key = None
            c.execute(
                """
                INSERT INTO repo_findings
                    (full_name, platform, url, detection_method, status, score,
                     code_hash, actor_key, reasoning, signals, matched_iocs,
                     first_seen_run, last_seen_run, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(full_name) DO UPDATE SET
                    platform = excluded.platform,
                    url = COALESCE(excluded.url, repo_findings.url),
                    status = CASE WHEN repo_findings.status = 'rejected'
                                  THEN 'rejected' ELSE excluded.status END,
                    score = excluded.score,
                    code_hash = COALESCE(excluded.code_hash, repo_findings.code_hash),
                    actor_key = COALESCE(repo_findings.actor_key, excluded.actor_key),
                    reasoning = excluded.reasoning,
                    signals = excluded.signals,
                    matched_iocs = excluded.matched_iocs,
                    raw_payload = excluded.raw_payload,
                    last_seen_run = excluded.last_seen_run
                """,
                (
                    finding.full_name,
                    finding.platform.value,
                    str(finding.url) if finding.url else None,
                    finding.detection_method.value,
                    finding.status.value,
                    finding.score,
                    finding.code_hash,
                    actor_key,
                    finding.reasoning,
                    json.dumps(finding.signals),
                    json.dumps(finding.matched_iocs),
                    run_id,
                    run_id,
                    json.dumps(finding.raw_payload, default=str),
                ),
            )

    def get_finding(self, full_name: str) -> sqlite3.Row | None:
        """Fetch a single repo finding by (normalized) full_name, or None."""
        return self.conn.execute(
            "SELECT * FROM repo_findings WHERE full_name = ?",
            (full_name.strip().strip("/").casefold(),),
        ).fetchone()

    def set_finding_status(self, full_name: str, status: str) -> int:
        """Analyst override of a finding's status (PRD 3). Returns rows changed."""
        with self.transaction() as c:
            cur = c.execute(
                "UPDATE repo_findings SET status = ? WHERE full_name = ?",
                (status, full_name.strip().strip("/").casefold()),
            )
            return cur.rowcount

    def reconcile_registry(self, known_good_owners: frozenset[str] = frozenset()) -> dict:
        """Precision sweep over CONFIRMED findings so the wall self-heals when the
        rules tighten. Rejects (sticky) a confirmed/validated finding when:

        * it has NO intrinsic static evidence (empty raw_payload['bash_findings'])
          -- an OSS-scanner-only or association-only confirmation, no file:line
          proof; or
        * its owner is in the known-good allowlist (a legit OSS org).

        redteam_lineage is left untouched: it is already excluded from publish (a
        breadcrumb that still feeds the IOC learning loop). Returns counts.
        """
        rows = self.conn.execute(
            "SELECT full_name, detection_method, raw_payload FROM repo_findings "
            "WHERE status IN ('confirmed', 'validated')"
        ).fetchall()
        unproven, known_good = [], []
        for r in rows:
            if r["full_name"].split("/", 1)[0].casefold() in known_good_owners:
                known_good.append(r["full_name"])
                continue
            if r["detection_method"] == "redteam_lineage":
                continue  # breadcrumb; never published, kept for IOC mining
            bash = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
            if not bash:
                unproven.append(r["full_name"])
        with self.transaction() as c:
            for fn in unproven + known_good:
                c.execute(
                    "UPDATE repo_findings SET status = 'rejected' WHERE full_name = ?", (fn,)
                )
        return {"rejected_unproven": len(unproven),
                "rejected_known_good": len(known_good)}

    def findings_by_status(self, status: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM repo_findings WHERE status = ? ORDER BY score DESC", (status,)
        ).fetchall()

    def published_findings(self) -> list[sqlite3.Row]:
        """Findings shown on the public Wall of Shame: confirmed (and any analyst-
        kept 'validated'), never rejected/screened/candidate. Highest score first.

        ASSOCIATION methods are EXCLUDED -- a repo is published only when it was
        DISCOVERED by intrinsic malware evidence (signature/ioc/package/osm),
        never by who owns it or what it forks:

        * redteam_lineage: a cloned/forked red-team tool is a breadcrumb, never
          provenance.
        * malicious_owner: guilt-by-association. The owner pivot enumerates a
          flagged owner's OTHER repos and confirms them on their own code, which
          pins whole legit security firms (e.g. NCC Group's published pen-test
          tools) and OSS orgs. Owner association seeds WHICH repos to scan and
          feeds the IOC learning loop, but never confirms one on the wall.
        * actor_account: "repo under a known threat-actor account" is the account
          being suspect, not this repo's code. Same breadcrumb treatment.
        """
        return self.conn.execute(
            "SELECT * FROM repo_findings WHERE status IN ('confirmed', 'validated') "
            "AND detection_method NOT IN "
            "('redteam_lineage', 'malicious_owner', 'actor_account') "
            "ORDER BY score DESC, full_name"
        ).fetchall()

    def findings_for_run(self, run_id: str) -> list[sqlite3.Row]:
        """Every repo this run touched (newly discovered or re-seen).

        Used by the findings artifact: all candidates are retained for audit,
        including screened and rejected ones (PRD section 13.1), so nothing is
        silently dropped. first_seen_run == run_id marks the genuinely new ones.
        """
        return self.conn.execute(
            "SELECT * FROM repo_findings WHERE last_seen_run = ? "
            "ORDER BY status, score DESC, full_name",
            (run_id,),
        ).fetchall()

    def undelivered_gold(self) -> list[sqlite3.Row]:
        """NOVEL confirmed findings not yet sent to Discord (gold queue).

        Gold is our contribution: malicious repos OSM does NOT already report.
        OSM-known repos (including everything from the osm_repository validation
        vector) are excluded; re-reporting them would just echo OSM's own intel.
        """
        known = self.osm_known_repos()
        rows = self.conn.execute(
            "SELECT * FROM repo_findings WHERE status = 'confirmed' AND delivered_gold = 0 "
            "AND detection_method NOT IN "
            "('osm_repository', 'redteam_lineage', 'malicious_owner', 'actor_account') "
            "ORDER BY score DESC"
        ).fetchall()
        return [r for r in rows if r["full_name"].casefold() not in known]

    def mark_gold_delivered(self, full_name: str) -> None:
        with self.transaction() as c:
            c.execute(
                "UPDATE repo_findings SET delivered_gold = 1 WHERE full_name = ?", (full_name,)
            )

    def actor_github_logins(self) -> list[tuple[str, str]]:
        """(actor_key, github login) pairs for actor-account discovery (doc 02 2.1).

        Only PROMOTED actors seed the search (eval finding #3): the layer acts on
        the validated dataset, so quarantined/rejected actors never drive
        discovery or attribution.
        """
        rows = self.conn.execute(
            "SELECT i.actor_key, i.value FROM actor_identifiers i "
            "JOIN threat_actors a ON a.actor_key = i.actor_key "
            "WHERE i.platform = 'github' "
            "AND i.identifier_type IN ('username', 'organization') "
            "AND a.status = 'promoted'"
        ).fetchall()
        return [(r["actor_key"], r["value"]) for r in rows]

    def known_repo_names(self) -> set[str]:
        """Every repo we already track, lowercased (eval finding #2).

        Union of OSM repo artifacts and existing findings, so discovery reports
        only genuinely-new repos. The caller adds pinned red-team tool repos.
        """
        from ..refs import repo_full_name

        known: set[str] = set()
        for row in self.list_artifacts(artifact_type="repo"):
            ref = json.loads(row["raw_payload"]).get("resource_identifier") or row["name"]
            full = repo_full_name(ref)
            if full:
                known.add(full.casefold())
        for row in self.conn.execute("SELECT full_name FROM repo_findings"):
            known.add(row["full_name"].casefold())
        return known

    def osm_known_repos(self) -> set[str]:
        """Repos OSM already reports (lowercased), from the repo artifacts.

        Git Warden's product is NOVEL malicious repos; ones OSM does not already
        have; which we contribute back. A confirmed repo already in OSM is used
        for detection VALIDATION, not re-reported to gold (it would just echo OSM's
        own intel back at them).
        """
        from ..refs import repo_full_name

        known: set[str] = set()
        for row in self.list_artifacts(artifact_type="repo"):
            ref = json.loads(row["raw_payload"]).get("resource_identifier") or row["name"]
            full = repo_full_name(ref)
            if full:
                known.add(full.casefold())
        return known

    def malicious_repo_owners(self) -> set[str]:
        """Proven-malicious-ACTOR owners: owners of a MALWARE repo WE confirmed.

        We deliberately do NOT seed from OSM repo ownership. OSM's "repository"
        field for a malicious package is the repo the malware impersonates /
        typosquats; i.e. the legitimate VICTIM, not the attacker. A heavily
        typosquatted legit org (e.g. tiledesk, 9 OSM entries) is indistinguishable
        from a prolific attacker by repo count, so counting OSM repos enumerated
        legit orgs and shipped their benign repos to gold.

        We also EXCLUDE red-team lineage confirmations. A weaponized-tool fork's
        author is typically a security researcher with a collection of offensive
        tools, not a prolific malware actor; seeding from them made the owner
        pivot enumerate researchers' benign clones (opencode, PentestGPT). Only an
        owner of a repo confirmed via a malware-discovery method seeds the pivot.
        OSM's package names drive expansion via :meth:`malicious_package_terms`.

        We also EXCLUDE owner-pivot (malicious_owner) confirmations from seeding,
        so the pivot cannot chain: an owner is "malicious" only when they own a
        repo confirmed by an INTRINSIC malware-discovery method, never merely
        because a sibling was itself owner-pivoted in.
        """
        return {
            row["full_name"].split("/", 1)[0]
            for row in self.conn.execute(
                "SELECT full_name FROM repo_findings "
                "WHERE status IN ('confirmed', 'validated') "
                "AND detection_method NOT IN ('redteam_lineage', 'malicious_owner')"
            )
        }

    def osm_repo_targets(self, limit: int = 0) -> list[tuple[str, str, dict]]:
        """OSM-labeled malicious repos to validate, as (full_name, url, intel).

        OSM pre-labels these malicious (mostly fake-interview / crypto-task lure
        repos). We do not trust the label; we clone and confirm via Tier-2 (a
        malware signature or a known-malicious dependency). ``intel`` carries OSM's
        own provenance (source, severity, tags, threat description) so a confirmed
        finding records WHO flagged it and the attribution (e.g. a 'dprk' tag).
        Repos already in the findings registry are skipped (already triaged).
        """
        from ..refs import repo_full_name

        seen = {
            row["full_name"].casefold()
            for row in self.conn.execute("SELECT full_name FROM repo_findings")
        }
        out: list[tuple[str, str, dict]] = []
        for row in self.list_artifacts(artifact_type="repo"):
            payload = json.loads(row["raw_payload"])
            ref = payload.get("resource_identifier") or row["name"]
            full = repo_full_name(ref)
            if not full or full.casefold() in seen:
                continue
            seen.add(full.casefold())
            url = ref if str(ref).startswith("http") else f"https://github.com/{full}"
            intel = {
                "source": row["source"],
                "severity": payload.get("severity_level"),
                "tags": payload.get("tags") or [],
                "threat": payload.get("threat_description")
                or payload.get("payload_description"),
            }
            out.append((full, url, intel))
            if limit and len(out) >= limit:
                break
        return out

    def malicious_dependency_names(self) -> dict[str, frozenset[str]]:
        """OSM-flagged package names per ECOSYSTEM, for manifest dependency match.

        Keyed by ecosystem ('npm', 'pypi') so a package.json dependency is matched
        only against npm malware and a requirements.txt only against pypi malware.
        Cross-ecosystem matching caused a false positive: the legit npm
        ``webpack-dev-server`` collided with a RubyGems typosquat of the same name.
        A repo declaring a match installs known malware on install (Tier-2
        confirmation). Ultra-short generic names are skipped (exact-match only).
        """
        out: dict[str, set[str]] = {"npm": set(), "pypi": set()}
        for row in self.list_artifacts(artifact_type="package"):
            eco = (row["ecosystem"] or "").strip().lower()
            if eco not in out:
                continue
            name = (row["name"] or "").strip().lower()
            if name.startswith("@") or len(name) >= 5:
                out[eco].add(name)
        return {eco: frozenset(names) for eco, names in out.items()}

    def malicious_package_terms(self, limit: int = 30) -> list[str]:
        """Distinctive malicious package names to code-search for (package pivot).

        Searching a malicious package name in code finds repos that install /
        distribute / depend on it. Generic short names are skipped to avoid noise.
        """
        terms: list[str] = []
        for row in self.list_artifacts(artifact_type="package"):
            name = (row["name"] or "").strip()
            if name.startswith("@") or len(name) >= 8:  # scoped or non-trivial
                terms.append(name)
        return list(dict.fromkeys(terms))[:limit]

    def cross_platform_clusters(self) -> dict[str, list[dict]]:
        """Confirmed findings grouped by code_hash (doc 04 section 6).

        The same malicious core re-hosted across platforms shares a code hash, so
        this collapses them into one tracked entity with multiple locations.
        Returns only clusters with more than one location.
        """
        clusters: dict[str, list[dict]] = {}
        rows = self.conn.execute(
            "SELECT code_hash, platform, full_name, url FROM repo_findings "
            "WHERE code_hash IS NOT NULL AND status = 'confirmed'"
        ).fetchall()
        for r in rows:
            clusters.setdefault(r["code_hash"], []).append(
                {"platform": r["platform"], "full_name": r["full_name"], "url": r["url"]}
            )
        return {h: locs for h, locs in clusters.items() if len(locs) > 1}

    #; learned IOCs (the compounding loop) -------------------------------
    def record_learned_ioc(self, value: str, kind: str, source_repo: str, run_id: str) -> None:
        """Store an IOC mined from a confirmed repo's code (dedup on value)."""
        with self.transaction() as c:
            c.execute(
                "INSERT OR IGNORE INTO learned_iocs (value, kind, source_repo, first_seen_run) "
                "VALUES (?, ?, ?, ?)",
                (value, kind, source_repo, run_id),
            )

    def learned_signatures(self) -> list[str]:
        """Code signatures mined from confirmed repos (kind='code_sig').

        These are deobfuscator-stub chunks searched on GitHub to find sibling
        infected repos; the novel-repo discovery loop.
        """
        return [
            row["value"]
            for row in self.conn.execute(
                "SELECT value FROM learned_iocs WHERE kind = 'code_sig'"
            )
        ]

    def learned_search_terms(self) -> list[str]:
        """Searchable strings from learned IOCs: domains + webhook ids."""
        import re

        terms: list[str] = []
        for row in self.conn.execute("SELECT value, kind FROM learned_iocs"):
            if row["kind"] == "domain":
                terms.append(row["value"])
            elif row["kind"] == "webhook":
                m = re.search(r"webhooks/(\d+)", row["value"])
                if m:
                    terms.append(m.group(1))
        return list(dict.fromkeys(terms))

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def actors_for_run(self, run_id: str) -> list[sqlite3.Row]:
        """All actors observed in a run, with their distinct-source count.

        Used by the artifacts writer: every candidate is retained for audit,
        including quarantined and rejected ones (PRD section 13.1).
        """
        return self.conn.execute(
            """
            SELECT
                a.actor_key,
                a.canonical_name,
                a.category,
                a.status,
                a.first_seen_run,
                a.last_seen_run,
                (SELECT COUNT(*) FROM actor_sources s WHERE s.actor_key = a.actor_key)
                    AS source_count
            FROM threat_actors a
            WHERE a.last_seen_run = ?
            ORDER BY source_count DESC, a.actor_key
            """,
            (run_id,),
        ).fetchall()

    def observation_counts_by_source(self, run_id: str) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT source, COUNT(*) AS n FROM source_observations "
            "WHERE run_id = ? GROUP BY source",
            (run_id,),
        ).fetchall()
        return {row["source"]: int(row["n"]) for row in rows}

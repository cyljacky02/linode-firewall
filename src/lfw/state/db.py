"""SQLite state and audit persistence layer."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from lfw.core.exceptions import StateDbError
from lfw.core.types import ApplyPlan, ApplyResult, SourceSnapshot

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(".lfw") / "state.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS source_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     TEXT NOT NULL,
    source_type   TEXT NOT NULL,
    url_or_command TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    fetched_at    TEXT NOT NULL,
    raw_count     INTEGER NOT NULL,
    normalized_count INTEGER NOT NULL,
    metadata_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS prefixes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES source_snapshots(id),
    cidr        TEXT NOT NULL,
    family      TEXT NOT NULL,
    provenance  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS policy_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name    TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT DEFAULT 'running',
    snapshot_refs  TEXT DEFAULT '[]',
    plan_json      TEXT DEFAULT '{}',
    result_json    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS summaries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES policy_runs(id),
    family      TEXT NOT NULL,
    input_count INTEGER NOT NULL,
    output_count INTEGER NOT NULL,
    expansion_ratio REAL NOT NULL,
    passed      INTEGER NOT NULL DEFAULT 1,
    detail      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS plans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES policy_runs(id),
    firewall_label  TEXT NOT NULL,
    create_firewall INTEGER NOT NULL DEFAULT 0,
    rules_changed   INTEGER NOT NULL DEFAULT 0,
    current_hash    TEXT DEFAULT '',
    desired_hash    TEXT DEFAULT '',
    payload_json    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS apply_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES policy_runs(id),
    action     TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    success    INTEGER NOT NULL DEFAULT 1,
    detail     TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS linode_observed_state (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_id    INTEGER NOT NULL,
    firewall_label TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    rules_hash     TEXT NOT NULL,
    rules_json     TEXT NOT NULL,
    devices_json   TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_snapshots_source ON source_snapshots(source_id);
CREATE INDEX IF NOT EXISTS idx_prefixes_snapshot ON prefixes(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_runs_policy ON policy_runs(policy_name);
CREATE INDEX IF NOT EXISTS idx_observed_fw ON linode_observed_state(firewall_id);
"""

CURRENT_SCHEMA_VERSION = 1


class StateDb:
    """SQLite-backed state and audit database."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._initialize()

    def _initialize(self) -> None:
        try:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA_SQL)

            cur = self._conn.execute("SELECT MAX(version) FROM schema_version")
            row = cur.fetchone()
            if row[0] is None:
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (CURRENT_SCHEMA_VERSION,),
                )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StateDbError(f"Failed to initialize state DB: {exc}") from exc

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Cursor, None, None]:
        assert self._conn is not None
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Source snapshots
    # ------------------------------------------------------------------
    def save_snapshot(self, snap: SourceSnapshot) -> int:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO source_snapshots
                   (source_id, source_type, url_or_command, sha256,
                    fetched_at, raw_count, normalized_count, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    snap.source_id,
                    snap.source_type,
                    snap.url_or_command,
                    snap.sha256,
                    snap.fetched_at.isoformat(),
                    snap.raw_count,
                    snap.normalized_count,
                    json.dumps(snap.metadata),
                ),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_latest_snapshot(self, source_id: str) -> dict | None:
        assert self._conn is not None
        cur = self._conn.execute(
            """SELECT * FROM source_snapshots
               WHERE source_id = ? ORDER BY id DESC LIMIT 1""",
            (source_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Policy runs
    # ------------------------------------------------------------------
    def start_run(self, policy_name: str, snapshot_refs: list[str]) -> int:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO policy_runs
                   (policy_name, started_at, status, snapshot_refs)
                   VALUES (?, ?, 'running', ?)""",
                (
                    policy_name,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(snapshot_refs),
                ),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def finish_run(
        self,
        run_id: int,
        status: str,
        plan: ApplyPlan | None = None,
        result: ApplyResult | None = None,
    ) -> None:
        plan_json = "{}"
        result_json = "{}"
        if plan:
            plan_json = json.dumps({
                "firewall_label": plan.firewall_label,
                "create": plan.create_firewall,
                "rules_changed": plan.rules_changed,
                "desired_hash": plan.desired_rules_hash,
            })
        if result:
            result_json = json.dumps({
                "success": result.success,
                "actions": result.actions_taken,
                "errors": result.errors,
            })

        with self._tx() as cur:
            cur.execute(
                """UPDATE policy_runs
                   SET finished_at = ?, status = ?,
                       plan_json = ?, result_json = ?
                   WHERE id = ?""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    plan_json,
                    result_json,
                    run_id,
                ),
            )

    # ------------------------------------------------------------------
    # Summarization records
    # ------------------------------------------------------------------
    def save_summary(self, run_id: int, report: dict) -> None:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO summaries
                   (run_id, family, input_count, output_count,
                    expansion_ratio, passed, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    report["family"],
                    report["input_count"],
                    report["output_count"],
                    report["expansion_ratio"],
                    1 if report.get("passed", True) else 0,
                    report.get("detail", ""),
                ),
            )

    # ------------------------------------------------------------------
    # Plans
    # ------------------------------------------------------------------
    def save_plan(self, run_id: int, plan: ApplyPlan) -> None:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO plans
                   (run_id, firewall_label, create_firewall, rules_changed,
                    current_hash, desired_hash, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    plan.firewall_label,
                    1 if plan.create_firewall else 0,
                    1 if plan.rules_changed else 0,
                    plan.current_rules_hash,
                    plan.desired_rules_hash,
                    json.dumps(plan.desired_payload),
                ),
            )

    # ------------------------------------------------------------------
    # Apply actions
    # ------------------------------------------------------------------
    def log_action(self, run_id: int, action: str, success: bool, detail: str = "") -> None:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO apply_actions
                   (run_id, action, timestamp, success, detail)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    run_id,
                    action,
                    datetime.now(timezone.utc).isoformat(),
                    1 if success else 0,
                    detail,
                ),
            )

    # ------------------------------------------------------------------
    # Observed state
    # ------------------------------------------------------------------
    def save_observed_state(
        self,
        firewall_id: int,
        firewall_label: str,
        rules_hash: str,
        rules_json: str,
        devices_json: str = "[]",
    ) -> None:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO linode_observed_state
                   (firewall_id, firewall_label, observed_at,
                    rules_hash, rules_json, devices_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    firewall_id,
                    firewall_label,
                    datetime.now(timezone.utc).isoformat(),
                    rules_hash,
                    rules_json,
                    devices_json,
                ),
            )

    def get_last_observed_state(self, firewall_label: str) -> dict | None:
        assert self._conn is not None
        cur = self._conn.execute(
            """SELECT * FROM linode_observed_state
               WHERE firewall_label = ? ORDER BY id DESC LIMIT 1""",
            (firewall_label,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def get_run_history(self, policy_name: str, limit: int = 20) -> list[dict]:
        assert self._conn is not None
        cur = self._conn.execute(
            """SELECT * FROM policy_runs
               WHERE policy_name = ? ORDER BY id DESC LIMIT ?""",
            (policy_name, limit),
        )
        return [dict(row) for row in cur.fetchall()]

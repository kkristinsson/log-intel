from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from log_intel.syslogb.app import config
from log_intel.syslogb.app.settings_registry import SECRET_KEYS, SETUP_COMPLETE_KEY, registry, registry_by_key


class AppStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or config.SQLITE_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_version (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        version INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS jobs (
                        id TEXT PRIMARY KEY,
                        file_path TEXT NOT NULL,
                        status TEXT NOT NULL,
                        mode TEXT,
                        created_at REAL NOT NULL,
                        finished_at REAL,
                        result_json TEXT,
                        raw_response TEXT,
                        error TEXT,
                        progress_pct INTEGER DEFAULT 0,
                        progress_stage TEXT DEFAULT ''
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        value_type TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings_meta (
                        key TEXT PRIMARY KEY,
                        label TEXT NOT NULL,
                        section TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        requires_restart INTEGER DEFAULT 0
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS columnizers (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL,
                        config_json TEXT NOT NULL,
                        file_glob TEXT NOT NULL DEFAULT '*',
                        priority INTEGER NOT NULL DEFAULT 0,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS timestamp_parsers (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL,
                        config_json TEXT NOT NULL,
                        file_glob TEXT NOT NULL DEFAULT '*',
                        priority INTEGER NOT NULL DEFAULT 0,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alert_rules (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        scope TEXT NOT NULL DEFAULT 'all',
                        query TEXT NOT NULL,
                        mode TEXT NOT NULL DEFAULT 'text',
                        log_dir TEXT,
                        file_glob TEXT,
                        cooldown_sec INTEGER NOT NULL DEFAULT 300,
                        webhook_url TEXT,
                        email_to TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alert_events (
                        id TEXT PRIMARY KEY,
                        rule_id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        line TEXT NOT NULL,
                        ts REAL,
                        channel TEXT NOT NULL,
                        status TEXT NOT NULL,
                        error TEXT,
                        created_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS saved_searches (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        query TEXT NOT NULL,
                        mode TEXT NOT NULL DEFAULT 'text',
                        scope TEXT NOT NULL DEFAULT 'all',
                        log_dir TEXT,
                        file_path TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                self._migrate_jobs(conn)
                self._migrate_schema(conn)
                self._ensure_analysis_schedules_table(conn)
                self._seed_meta(conn)
                conn.commit()
            finally:
                conn.close()

    def _ensure_analysis_schedules_table(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_schedules (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_days INTEGER NOT NULL DEFAULT 1,
                run_at_hour INTEGER NOT NULL DEFAULT 2,
                scope TEXT NOT NULL DEFAULT 'full',
                window TEXT DEFAULT '',
                    min_severity TEXT NOT NULL DEFAULT 'warning',
                alert_on_anomalies INTEGER NOT NULL DEFAULT 1,
                webhook_url TEXT DEFAULT '',
                email_to TEXT DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_run_at REAL,
                last_job_id TEXT,
                last_status TEXT,
                last_error TEXT,
                next_run_at REAL
            )
            """
        )

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT version FROM schema_version WHERE id=1").fetchone()
        if not row:
            conn.execute("INSERT INTO schema_version (id, version) VALUES (1, 3)")
            self._ensure_analysis_schedules_table(conn)
            conn.execute("UPDATE schema_version SET version=4 WHERE id=1")
            return
        version = row["version"]
        if version < 3:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS saved_searches (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    query TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'text',
                    scope TEXT NOT NULL DEFAULT 'all',
                    log_dir TEXT,
                    file_path TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            version = 3
            conn.execute("UPDATE schema_version SET version=3 WHERE id=1")
        if version < 4:
            self._ensure_analysis_schedules_table(conn)
            conn.execute("UPDATE schema_version SET version=4 WHERE id=1")

    def _migrate_jobs(self, conn: sqlite3.Connection) -> None:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
        if "progress_pct" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN progress_pct INTEGER DEFAULT 0")
        if "progress_stage" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN progress_stage TEXT DEFAULT ''")

    def _seed_meta(self, conn: sqlite3.Connection) -> None:
        for d in registry():
            conn.execute(
                """
                INSERT OR IGNORE INTO settings_meta
                (key, label, section, description, requires_restart)
                VALUES (?, ?, ?, ?, ?)
                """,
                (d.key, d.label, d.section, d.description, 1 if d.requires_restart else 0),
            )

    def seed_settings_if_empty(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                now = time.time()
                col_count = conn.execute("SELECT COUNT(*) FROM columnizers").fetchone()[0]
                if col_count == 0:
                    self._seed_builtin_columnizers(conn, now)
                self._upgrade_builtin_columnizers(conn, now)
                self._seed_builtin_timestamp_parsers(conn, now)
                conn.commit()
            finally:
                conn.close()

    def seed_settings_values_from_env_if_empty(self) -> bool:
        """First install: copy .env values (or registry defaults) into settings.

        Does not set SETUP_COMPLETE — the setup wizard still runs on first visit.
        """
        with self._lock:
            conn = self._connect()
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM settings WHERE key != ?",
                    (SETUP_COMPLETE_KEY,),
                ).fetchone()[0]
                if count > 0:
                    return False
                now = time.time()
                for d in registry():
                    if d.key == SETUP_COMPLETE_KEY:
                        continue
                    env_val = os.environ.get(d.key)
                    value = env_val if env_val is not None and env_val != "" else d.default
                    conn.execute(
                        """
                        INSERT INTO settings (key, value, value_type, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (d.key, value, d.value_type, now),
                    )
                conn.commit()
                return True
            finally:
                conn.close()

    def _seed_builtin_columnizers(self, conn: sqlite3.Connection, now: float) -> None:
        builtins = [
            ("builtin-syslog", "Syslog", "syslog", "{}", "syslog,messages,*.log", 10),
            ("builtin-csv", "CSV", "csv", json.dumps({"delimiter": ",", "quote": '"'}), "*.csv", 5),
        ]
        for cid, name, ctype, cfg, glob, pri in builtins:
            conn.execute(
                """
                INSERT OR IGNORE INTO columnizers
                (id, name, type, config_json, file_glob, priority, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (cid, name, ctype, cfg, glob, pri, now, now),
            )

    def _upgrade_builtin_columnizers(self, conn: sqlite3.Connection, now: float) -> None:
        conn.execute(
            """
            UPDATE columnizers
            SET file_glob=?, updated_at=?
            WHERE id=? AND file_glob=?
            """,
            ("syslog,messages,*.log", now, "builtin-syslog", "*.log"),
        )

    def _seed_builtin_timestamp_parsers(self, conn: sqlite3.Connection, now: float) -> None:
        sms_pri_cfg = {
            "pattern": (
                r"\[sms\.(?P<event_date>\d{4}-\d{2}-\d{2})\]"
                r"(?:\s*-\s+(?P<event_time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[)?"
            ),
            "date_group": "event_date",
            "time_group": "event_time",
            "time_default": "00:00:00",
        }
        builtins = [
            ("builtin-sms-pri", "SMS Pri logs", "regex", json.dumps(sms_pri_cfg), "Pri.log", 15),
        ]
        for pid, name, ptype, cfg, glob, pri in builtins:
            conn.execute(
                """
                INSERT OR IGNORE INTO timestamp_parsers
                (id, name, type, config_json, file_glob, priority, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (pid, name, ptype, cfg, glob, pri, now, now),
            )

    # --- Settings ---

    def get(self, key: str) -> str | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            finally:
                conn.close()
        return row["value"] if row else None

    def set_many(self, updates: dict[str, str]) -> None:
        now = time.time()
        defs = registry_by_key()
        with self._lock:
            conn = self._connect()
            try:
                for key, value in updates.items():
                    if key == SETUP_COMPLETE_KEY:
                        conn.execute(
                            """
                            INSERT INTO settings (key, value, value_type, updated_at)
                            VALUES (?, ?, 'bool', ?)
                            ON CONFLICT(key) DO UPDATE SET
                              value=excluded.value, updated_at=excluded.updated_at
                            """,
                            (key, value, now),
                        )
                        continue
                    if key not in defs:
                        continue
                    if key in SECRET_KEYS and value == "":
                        continue
                    conn.execute(
                        """
                        INSERT INTO settings (key, value, value_type, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(key) DO UPDATE SET
                          value=excluded.value, updated_at=excluded.updated_at
                        """,
                        (key, value, defs[key].value_type, now),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_settings_grouped(self) -> dict[str, list[dict[str, Any]]]:
        from log_intel.syslogb.app.runtime_config import effective_value

        defs = registry_by_key()
        with self._lock:
            conn = self._connect()
            try:
                meta_rows = conn.execute("SELECT * FROM settings_meta ORDER BY section, key").fetchall()
            finally:
                conn.close()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in meta_rows:
            key = row["key"]
            d = defs.get(key)
            if not d:
                continue
            val, source = effective_value(key, self)
            is_secret = key in SECRET_KEYS or d.value_type == "secret"
            configured = bool(val) if is_secret else None
            entry = {
                "key": key,
                "label": row["label"],
                "section": row["section"],
                "description": row["description"],
                "requires_restart": bool(row["requires_restart"]),
                "value_type": d.value_type,
                "value": "" if is_secret else val,
                "configured": configured,
                "source": source,
                "editable": True,
                "secret": is_secret,
            }
            grouped.setdefault(row["section"], []).append(entry)
        return grouped

    def is_setup_complete(self) -> bool:
        return self.get(SETUP_COMPLETE_KEY) == "1"

    def mark_setup_complete(self) -> None:
        self.set_many({SETUP_COMPLETE_KEY: "1"})

    def ensure_legacy_setup_complete(self) -> None:
        """Mark setup done for databases created before SETUP_COMPLETE existed."""
        if self.is_setup_complete():
            return
        with self._lock:
            conn = self._connect()
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM settings WHERE key != ?",
                    (SETUP_COMPLETE_KEY,),
                ).fetchone()[0]
            finally:
                conn.close()
        if count > 0:
            self.mark_setup_complete()

    # --- Columnizers ---

    def list_columnizers(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM columnizers ORDER BY priority DESC, name"
                ).fetchall()
            finally:
                conn.close()
        return [self._columnizer_row(r) for r in rows]

    def _columnizer_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "type": row["type"],
            "config": json.loads(row["config_json"] or "{}"),
            "file_glob": row["file_glob"],
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_columnizer(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        cid = data.get("id") or uuid.uuid4().hex
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO columnizers
                    (id, name, type, config_json, file_glob, priority, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      name=excluded.name, type=excluded.type, config_json=excluded.config_json,
                      file_glob=excluded.file_glob, priority=excluded.priority,
                      enabled=excluded.enabled, updated_at=excluded.updated_at
                    """,
                    (
                        cid,
                        data["name"],
                        data["type"],
                        json.dumps(data.get("config") or {}),
                        data.get("file_glob", "*"),
                        int(data.get("priority", 0)),
                        1 if data.get("enabled", True) else 0,
                        data.get("created_at", now),
                        now,
                    ),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM columnizers WHERE id=?", (cid,)).fetchone()
            finally:
                conn.close()
        return self._columnizer_row(row)

    def delete_columnizer(self, cid: str) -> bool:
        if cid.startswith("builtin-"):
            return False
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM columnizers WHERE id=?", (cid,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # --- Timestamp parsers ---

    def list_timestamp_parsers(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM timestamp_parsers ORDER BY priority DESC, name"
                ).fetchall()
            finally:
                conn.close()
        return [self._timestamp_parser_row(r) for r in rows]

    def _timestamp_parser_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "type": row["type"],
            "config": json.loads(row["config_json"] or "{}"),
            "file_glob": row["file_glob"],
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_timestamp_parser(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        pid = data.get("id") or uuid.uuid4().hex
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO timestamp_parsers
                    (id, name, type, config_json, file_glob, priority, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      name=excluded.name, type=excluded.type, config_json=excluded.config_json,
                      file_glob=excluded.file_glob, priority=excluded.priority,
                      enabled=excluded.enabled, updated_at=excluded.updated_at
                    """,
                    (
                        pid,
                        data["name"],
                        data["type"],
                        json.dumps(data.get("config") or {}),
                        data.get("file_glob", "*"),
                        int(data.get("priority", 0)),
                        1 if data.get("enabled", True) else 0,
                        data.get("created_at", now),
                        now,
                    ),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM timestamp_parsers WHERE id=?", (pid,)
                ).fetchone()
            finally:
                conn.close()
        return self._timestamp_parser_row(row)

    def delete_timestamp_parser(self, pid: str) -> bool:
        if pid.startswith("builtin-"):
            return False
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM timestamp_parsers WHERE id=?", (pid,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # --- Alert rules ---

    def list_alert_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM alert_rules ORDER BY name"
                ).fetchall()
            finally:
                conn.close()
        return [self._alert_rule_row(r) for r in rows]

    def _alert_rule_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "enabled": bool(row["enabled"]),
            "scope": row["scope"],
            "query": row["query"],
            "mode": row["mode"],
            "log_dir": row["log_dir"],
            "file_glob": row["file_glob"],
            "cooldown_sec": row["cooldown_sec"],
            "webhook_url": row["webhook_url"],
            "email_to": row["email_to"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_alert_rule(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        rid = data.get("id") or uuid.uuid4().hex
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO alert_rules
                    (id, name, enabled, scope, query, mode, log_dir, file_glob,
                     cooldown_sec, webhook_url, email_to, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      name=excluded.name, enabled=excluded.enabled, scope=excluded.scope,
                      query=excluded.query, mode=excluded.mode, log_dir=excluded.log_dir,
                      file_glob=excluded.file_glob, cooldown_sec=excluded.cooldown_sec,
                      webhook_url=excluded.webhook_url, email_to=excluded.email_to,
                      updated_at=excluded.updated_at
                    """,
                    (
                        rid,
                        data["name"],
                        1 if data.get("enabled", True) else 0,
                        data.get("scope", "all"),
                        data["query"],
                        data.get("mode", "text"),
                        data.get("log_dir"),
                        data.get("file_glob"),
                        int(data.get("cooldown_sec", 300)),
                        data.get("webhook_url"),
                        data.get("email_to"),
                        data.get("created_at", now),
                        now,
                    ),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM alert_rules WHERE id=?", (rid,)).fetchone()
            finally:
                conn.close()
        return self._alert_rule_row(row)

    def delete_alert_rule(self, rid: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def record_alert_event(
        self,
        rule_id: str,
        source: str,
        line: str,
        ts: float | None,
        channel: str,
        status: str,
        error: str = "",
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO alert_events
                    (id, rule_id, source, line, ts, channel, status, error, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (uuid.uuid4().hex, rule_id, source, line, ts, channel, status, error, time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def list_alert_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM alert_events ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        return [
            {
                "id": r["id"],
                "rule_id": r["rule_id"],
                "source": r["source"],
                "line": r["line"],
                "ts": r["ts"],
                "channel": r["channel"],
                "status": r["status"],
                "error": r["error"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # --- Saved searches (global shared list) ---

    def list_saved_searches(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM saved_searches ORDER BY name COLLATE NOCASE"
                ).fetchall()
            finally:
                conn.close()
        return [self._saved_search_row(r) for r in rows]

    def _saved_search_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "query": row["query"],
            "mode": row["mode"],
            "scope": row["scope"],
            "log_dir": row["log_dir"],
            "file_path": row["file_path"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_saved_search(self, data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        sid = data.get("id") or uuid.uuid4().hex
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO saved_searches
                    (id, name, query, mode, scope, log_dir, file_path, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      name=excluded.name, query=excluded.query, mode=excluded.mode,
                      scope=excluded.scope, log_dir=excluded.log_dir,
                      file_path=excluded.file_path, updated_at=excluded.updated_at
                    """,
                    (
                        sid,
                        data["name"],
                        data["query"],
                        data.get("mode", "text"),
                        data.get("scope", "all"),
                        data.get("log_dir"),
                        data.get("file_path"),
                        data.get("created_at", now),
                        now,
                    ),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM saved_searches WHERE id=?", (sid,)).fetchone()
            finally:
                conn.close()
        return self._saved_search_row(row)

    def delete_saved_search(self, sid: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM saved_searches WHERE id=?", (sid,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    # --- Analysis jobs (unchanged API) ---

    def update_job_progress(self, job_id: str, pct: int, stage: str) -> None:
        pct = max(0, min(100, int(pct)))
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE jobs SET progress_pct=?, progress_stage=? WHERE id=?",
                    (pct, stage, job_id),
                )
                conn.commit()
            finally:
                conn.close()

    def create_job(self, file_path: str, mode: str = "auto") -> str:
        job_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO jobs (id, file_path, status, mode, created_at) VALUES (?, ?, ?, ?, ?)",
                    (job_id, file_path, "pending", mode, now),
                )
                conn.commit()
            finally:
                conn.close()
        return job_id

    def update_job(
        self,
        job_id: str,
        *,
        status: str,
        result: Optional[dict[str, Any]] = None,
        raw: str = "",
        error: str = "",
    ) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE jobs SET status=?, finished_at=?, result_json=?, raw_response=?, error=?
                    WHERE id=?
                    """,
                    (
                        status,
                        now,
                        json.dumps(result) if result else None,
                        raw or None,
                        error or None,
                        job_id,
                    ),
                )
                conn.commit()
                if status in ("done", "error"):
                    self._prune_analysis_history(conn)
            finally:
                conn.close()

    def analysis_history_keep(self) -> int:
        from log_intel.syslogb.app import config

        return max(1, min(50, int(getattr(config, "ANALYSIS_HISTORY_KEEP", 5) or 5)))

    def _prune_analysis_history(self, conn: sqlite3.Connection) -> None:
        """Keep only the newest finished analyses (done/error)."""
        keep = self.analysis_history_keep()
        rows = conn.execute(
            """
            SELECT id FROM jobs
            WHERE status IN ('done', 'error')
            ORDER BY COALESCE(finished_at, created_at) DESC
            """
        ).fetchall()
        if len(rows) <= keep:
            return
        drop_ids = [r[0] for r in rows[keep:]]
        placeholders = ",".join("?" * len(drop_ids))
        conn.execute(f"DELETE FROM jobs WHERE id IN ({placeholders})", drop_ids)
        conn.commit()

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    UPDATE jobs SET status='cancelled', finished_at=?, error=?
                    WHERE id=? AND status IN ('pending', 'running')
                    """,
                    (time.time(), "Cancelled by user", job_id),
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        result = None
        if row["result_json"]:
            try:
                result = json.loads(row["result_json"])
            except json.JSONDecodeError:
                result = None
        return {
            "id": row["id"],
            "file_path": row["file_path"],
            "status": row["status"],
            "mode": row["mode"],
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "result": result,
            "raw_response": row["raw_response"],
            "error": row["error"],
            "progress_pct": row["progress_pct"],
            "progress_stage": row["progress_stage"],
        }

    def list_saved_analyses(self, limit: int = 5) -> list[dict[str, Any]]:
        """Recent finished analyses kept for the history UI (newest first)."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT id, file_path, status, mode, created_at, finished_at,
                           result_json, error
                    FROM jobs
                    WHERE status IN ('done', 'error')
                      AND (result_json IS NOT NULL OR (error IS NOT NULL AND error != ''))
                    ORDER BY COALESCE(finished_at, created_at) DESC
                    LIMIT ?
                    """,
                    (max(1, int(limit)),),
                ).fetchall()
            finally:
                conn.close()
        out: list[dict[str, Any]] = []
        for row in rows:
            result = None
            if row["result_json"]:
                try:
                    result = json.loads(row["result_json"])
                except json.JSONDecodeError:
                    result = None
            summary = ""
            severity = ""
            if isinstance(result, dict):
                summary = str(result.get("summary", "")).strip()
                severity = str(result.get("severity", "")).strip()
            out.append({
                "id": row["id"],
                "file_path": row["file_path"],
                "file_name": Path(row["file_path"]).name,
                "status": row["status"],
                "mode": row["mode"],
                "created_at": row["created_at"],
                "finished_at": row["finished_at"],
                "result": result,
                "summary": summary,
                "severity": severity,
                "error": row["error"],
            })
        return out

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        out = []
        for row in rows:
            result = None
            if row["result_json"]:
                try:
                    result = json.loads(row["result_json"])
                except json.JSONDecodeError:
                    pass
            out.append({
                "id": row["id"],
                "file_path": row["file_path"],
                "status": row["status"],
                "mode": row["mode"],
                "created_at": row["created_at"],
                "finished_at": row["finished_at"],
                "result": result,
                "error": row["error"],
                "progress_pct": row["progress_pct"],
                "progress_stage": row["progress_stage"],
            })
        return out

    def _analysis_schedule_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "file_path": row["file_path"],
            "file_name": Path(row["file_path"]).name,
            "enabled": bool(row["enabled"]),
            "interval_days": int(row["interval_days"]),
            "run_at_hour": int(row["run_at_hour"]),
            "scope": row["scope"] or "full",
            "window": row["window"] or "",
            "min_severity": row["min_severity"] or "medium",
            "alert_on_anomalies": bool(row["alert_on_anomalies"]),
            "webhook_url": row["webhook_url"] or "",
            "email_to": row["email_to"] or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_run_at": row["last_run_at"],
            "last_job_id": row["last_job_id"],
            "last_status": row["last_status"],
            "last_error": row["last_error"],
            "next_run_at": row["next_run_at"],
        }

    def list_analysis_schedules(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM analysis_schedules ORDER BY file_path"
                ).fetchall()
            finally:
                conn.close()
        return [self._analysis_schedule_row(r) for r in rows]

    def get_analysis_schedule(self, schedule_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM analysis_schedules WHERE id=?",
                    (schedule_id,),
                ).fetchone()
            finally:
                conn.close()
        return self._analysis_schedule_row(row) if row else None

    def get_analysis_schedule_for_path(self, file_path: str) -> Optional[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM analysis_schedules WHERE file_path=?",
                    (file_path,),
                ).fetchone()
            finally:
                conn.close()
        return self._analysis_schedule_row(row) if row else None

    def list_due_analysis_schedules(self, now: float) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM analysis_schedules
                    WHERE enabled=1 AND next_run_at IS NOT NULL AND next_run_at <= ?
                    ORDER BY next_run_at
                    """,
                    (now,),
                ).fetchall()
            finally:
                conn.close()
        return [self._analysis_schedule_row(r) for r in rows]

    def upsert_analysis_schedule(self, data: dict[str, Any]) -> dict[str, Any]:
        rid = (data.get("id") or "").strip() or uuid.uuid4().hex
        file_path = str(data.get("file_path", "")).strip()
        if not file_path:
            raise ValueError("file_path required")
        interval_days = int(data.get("interval_days", 1))
        if interval_days not in (1, 2, 7):
            raise ValueError("interval_days must be 1, 2, or 7")
        run_at_hour = max(0, min(23, int(data.get("run_at_hour", 2))))
        scope = (data.get("scope") or "full").strip().lower()
        if scope not in ("full", "window"):
            raise ValueError("scope must be 'full' or 'window'")
        window = (data.get("window") or "").strip().lower()
        min_severity = (data.get("min_severity") or "medium").strip().lower()
        now = time.time()
        next_run = data.get("next_run_at")
        if next_run is None:
            from log_intel.syslogb.app.analysis_scheduler import compute_next_run

            next_run = compute_next_run(interval_days, run_at_hour, after=now)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO analysis_schedules (
                        id, file_path, enabled, interval_days, run_at_hour, scope, window,
                        min_severity, alert_on_anomalies, webhook_url, email_to,
                        created_at, updated_at, next_run_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        enabled=excluded.enabled,
                        interval_days=excluded.interval_days,
                        run_at_hour=excluded.run_at_hour,
                        scope=excluded.scope,
                        window=excluded.window,
                        min_severity=excluded.min_severity,
                        alert_on_anomalies=excluded.alert_on_anomalies,
                        webhook_url=excluded.webhook_url,
                        email_to=excluded.email_to,
                        updated_at=excluded.updated_at,
                        next_run_at=excluded.next_run_at
                    """,
                    (
                        rid,
                        file_path,
                        1 if data.get("enabled", True) else 0,
                        interval_days,
                        run_at_hour,
                        scope,
                        window,
                        min_severity,
                        1 if data.get("alert_on_anomalies", True) else 0,
                        (data.get("webhook_url") or "").strip(),
                        (data.get("email_to") or "").strip(),
                        now,
                        now,
                        float(next_run),
                    ),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM analysis_schedules WHERE file_path=?",
                    (file_path,),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            raise RuntimeError("schedule upsert failed")
        return self._analysis_schedule_row(row)

    def update_analysis_schedule_run(
        self,
        schedule_id: str,
        *,
        last_run_at: float | None = None,
        last_job_id: str | None = None,
        last_status: str | None = None,
        last_error: str | None = None,
        next_run_at: float | None = None,
    ) -> None:
        fields: list[str] = []
        values: list[Any] = []
        if last_run_at is not None:
            fields.append("last_run_at=?")
            values.append(last_run_at)
        if last_job_id is not None:
            fields.append("last_job_id=?")
            values.append(last_job_id)
        if last_status is not None:
            fields.append("last_status=?")
            values.append(last_status)
        if last_error is not None:
            fields.append("last_error=?")
            values.append(last_error)
        if next_run_at is not None:
            fields.append("next_run_at=?")
            values.append(next_run_at)
        if not fields:
            return
        fields.append("updated_at=?")
        values.append(time.time())
        values.append(schedule_id)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE analysis_schedules SET {', '.join(fields)} WHERE id=?",
                    values,
                )
                conn.commit()
            finally:
                conn.close()

    def delete_analysis_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "DELETE FROM analysis_schedules WHERE id=?", (schedule_id,)
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def delete_analysis_schedule_for_path(self, file_path: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "DELETE FROM analysis_schedules WHERE file_path=?", (file_path,)
                )
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()


# Backward compatibility alias
AnalysisStore = AppStore
SettingsStore = AppStore

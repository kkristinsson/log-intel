"""Unified SQLite storage for log-intel."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from log_intel.models import LogEvent, StreamEvent
from log_intel.store_loggy import LogStoreMixin, RawLogRow, migrate_schema_v2

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at REAL NOT NULL,
    source_id TEXT NOT NULL DEFAULT 'hub',
    source_type TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    transport TEXT NOT NULL,
    syslog_host TEXT,
    facility INTEGER,
    severity INTEGER,
    raw TEXT,
    message TEXT NOT NULL,
    parser TEXT NOT NULL,
    log_type TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT,
    action TEXT,
    event_ts REAL,
    src_lat REAL,
    src_lon REAL,
    src_country TEXT,
    dst_lat REAL,
    dst_lon REAL,
    dst_country TEXT,
    llm_severity TEXT,
    llm_summary TEXT,
    analysis_id INTEGER,
    analyzed_at REAL
);

CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_log_type ON events(log_type);
CREATE INDEX IF NOT EXISTS idx_events_src_dst ON events(src_ip, dst_ip);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    scope TEXT NOT NULL,
    params_json TEXT,
    result_json TEXT,
    error TEXT,
    created_at REAL NOT NULL,
    finished_at REAL
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    query TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'text',
    source_type TEXT,
    scope TEXT NOT NULL DEFAULT 'all',
    cooldown_sec INTEGER NOT NULL DEFAULT 300,
    webhook_url TEXT,
    email_to TEXT,
    log_dir TEXT,
    file_glob TEXT,
    created_at REAL NOT NULL,
    updated_at REAL
);

CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    source TEXT NOT NULL,
    line TEXT NOT NULL,
    ts REAL NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT,
    origin TEXT NOT NULL DEFAULT 'hub',
    channel TEXT,
    status TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts DESC);
"""

EVENT_SELECT = """
SELECT id, received_at, source_id, source_type, remote_ip, transport, syslog_host,
       facility, severity, raw, message, parser, log_type, src_ip, dst_ip,
       src_port, dst_port, proto, action, event_ts,
       src_lat, src_lon, src_country, dst_lat, dst_lon, dst_country,
       llm_severity, llm_summary, analysis_id, analyzed_at
FROM events
"""


class EventStore(LogStoreMixin):
    def __init__(self, path: str, max_events: int = 500_000) -> None:
        self._path = path
        self._max_events = max_events
        self._lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(SCHEMA)
        migrate_schema_v2(self._conn)
        cur = self._conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cur.fetchone()
        if row is None:
            self._conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
        elif row[0] < SCHEMA_VERSION:
            migrate_schema_v2(self._conn)
            self._conn.execute("UPDATE schema_version SET version=?", (SCHEMA_VERSION,))
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def has_parser(self, parser: str) -> bool:
        if not parser:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM events WHERE parser = ? LIMIT 1",
                (parser,),
            ).fetchone()
        return row is not None

    def insert(self, ev: LogEvent) -> int:
        row = ev.to_insert_row()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO events (
                    received_at, source_id, source_type, remote_ip, transport, syslog_host,
                    facility, severity, raw, message, parser, log_type,
                    src_ip, dst_ip, src_port, dst_port, proto, action, event_ts,
                    src_lat, src_lon, src_country, dst_lat, dst_lon, dst_country
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                row,
            )
            eid = int(cur.lastrowid)
            self._prune_events_locked()
            self._conn.commit()
            return eid

    def _prune_events_locked(self) -> None:
        if self._max_events <= 0:
            return
        cur = self._conn.execute("SELECT COUNT(*) FROM events")
        count = cur.fetchone()[0]
        if count > self._max_events:
            excess = count - self._max_events
            self._conn.execute(
                """DELETE FROM events WHERE id IN (
                    SELECT id FROM events ORDER BY id ASC LIMIT ?
                )""",
                (excess,),
            )

    def get_event(self, event_id: int) -> LogEvent | None:
        with self._lock:
            cur = self._conn.execute(f"{EVENT_SELECT} WHERE id = ?", (event_id,))
            row = cur.fetchone()
        return LogEvent.from_row(row) if row else None

    def list_events(
        self,
        *,
        since: float | None = None,
        until: float | None = None,
        source_type: str | None = None,
        log_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order: str = "desc",
    ) -> list[LogEvent]:
        where: list[str] = []
        params: list[Any] = []
        if since is not None:
            where.append("received_at >= ?")
            params.append(since)
        if until is not None:
            where.append("received_at <= ?")
            params.append(until)
        if source_type:
            where.append("source_type = ?")
            params.append(source_type)
        if log_type:
            where.append("log_type = ?")
            params.append(log_type)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        direction = "DESC" if order.lower() != "asc" else "ASC"
        params.extend([limit, offset])
        with self._lock:
            cur = self._conn.execute(
                f"{EVENT_SELECT} {cond} ORDER BY received_at {direction} LIMIT ? OFFSET ?",
                params,
            )
            rows = cur.fetchall()
        return [LogEvent.from_row(r) for r in rows]

    def search(
        self,
        q: str,
        *,
        mode: str = "text",
        source_type: str | None = None,
        since: float | None = None,
        limit: int = 200,
    ) -> list[LogEvent]:
        where: list[str] = []
        params: list[Any] = []
        if since is not None:
            where.append("received_at >= ?")
            params.append(since)
        if source_type:
            where.append("source_type = ?")
            params.append(source_type)
        if mode != "regex":
            terms = [t for t in q.lower().split() if t]
            for term in terms:
                where.append("LOWER(message) LIKE ?")
                params.append(f"%{term}%")
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        fetch_limit = limit * 5 if mode == "regex" else limit
        params.append(fetch_limit)
        with self._lock:
            cur = self._conn.execute(
                f"{EVENT_SELECT} {cond} ORDER BY received_at DESC LIMIT ?",
                params,
            )
            rows = cur.fetchall()
        events = [LogEvent.from_row(r) for r in rows]
        if mode == "regex":
            import re

            try:
                pat = re.compile(q, re.IGNORECASE)
                events = [e for e in events if pat.search(e.message or "")]
            except re.error:
                events = []
        return events[:limit]

    def flow_aggregates(
        self,
        since: float | None,
        until: float | None,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        where: list[str] = ["src_ip IS NOT NULL", "dst_ip IS NOT NULL"]
        params: list[Any] = []
        if since is not None:
            where.append("COALESCE(event_ts, received_at) >= ?")
            params.append(since)
        if until is not None:
            where.append("COALESCE(event_ts, received_at) <= ?")
            params.append(until)
        cond = "WHERE " + " AND ".join(where)
        sql = f"""
            SELECT
              src_ip, dst_ip,
              COUNT(*) AS cnt,
              MAX(src_lat) AS src_lat, MAX(src_lon) AS src_lon, MAX(src_country) AS src_country,
              MAX(dst_lat) AS dst_lat, MAX(dst_lon) AS dst_lon, MAX(dst_country) AS dst_country
            FROM events
            {cond}
            GROUP BY src_ip, dst_ip
            HAVING src_lat IS NOT NULL AND dst_lat IS NOT NULL
            ORDER BY cnt DESC
            LIMIT ?
        """
        params.append(limit)
        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def delete_older_than(self, cutoff_ts: float) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM events WHERE received_at < ?", (cutoff_ts,)
            )
            self._conn.commit()
            return cur.rowcount or 0

    def count_events(self, since: float | None = None) -> int:
        with self._lock:
            if since is None:
                cur = self._conn.execute("SELECT COUNT(*) FROM events")
            else:
                cur = self._conn.execute(
                    "SELECT COUNT(*) FROM events WHERE received_at >= ?", (since,)
                )
            return int(cur.fetchone()[0])

    def count_events_by_source_type(self, source_type: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE source_type = ?",
                (source_type,),
            )
            return int(cur.fetchone()[0])

    def unanalyzed_events(self, limit: int = 10) -> list[LogEvent]:
        with self._lock:
            cur = self._conn.execute(
                f"""{EVENT_SELECT}
                WHERE analyzed_at IS NULL AND source_type IN ('palo_alto', 'generic', 'windows')
                ORDER BY id ASC LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
        return [LogEvent.from_row(r) for r in rows]

    def mark_analyzed(
        self,
        event_ids: list[int],
        analysis_id: int,
        severity: str,
        summary: str,
    ) -> None:
        now = time.time()
        with self._lock:
            for eid in event_ids:
                self._conn.execute(
                    """UPDATE events SET analyzed_at = ?, analysis_id = ?,
                       llm_severity = ?, llm_summary = ? WHERE id = ?""",
                    (now, analysis_id, severity, summary, eid),
                )
            self._conn.commit()

    def create_analysis_job(self, scope: str, params: dict[str, Any] | None = None) -> str:
        job_id = uuid.uuid4().hex[:16]
        with self._lock:
            self._conn.execute(
                """INSERT INTO analysis_jobs (job_id, status, scope, params_json, created_at)
                   VALUES (?, 'pending', ?, ?, ?)""",
                (job_id, scope, json.dumps(params or {}), time.time()),
            )
            self._conn.commit()
        return job_id

    def update_analysis_job(
        self,
        job_id: str,
        *,
        status: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            if status == "done" or status == "failed":
                self._conn.execute(
                    """UPDATE analysis_jobs SET status = ?, result_json = ?, error = ?,
                       finished_at = ? WHERE job_id = ?""",
                    (
                        status,
                        json.dumps(result) if result else None,
                        error,
                        time.time(),
                        job_id,
                    ),
                )
            elif status:
                self._conn.execute(
                    "UPDATE analysis_jobs SET status = ? WHERE job_id = ?",
                    (status, job_id),
                )
            self._conn.commit()

    def get_analysis_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT job_id, status, scope, params_json, result_json, error, created_at, finished_at "
                "FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "job_id": row[0],
            "status": row[1],
            "scope": row[2],
            "params": json.loads(row[3]) if row[3] else {},
            "result": json.loads(row[4]) if row[4] else None,
            "error": row[5],
            "created_at": row[6],
            "finished_at": row[7],
        }

    def list_alert_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, name, enabled, query, mode, source_type, scope, cooldown_sec,
                          webhook_url, email_to, log_dir, file_glob
                   FROM alert_rules ORDER BY name"""
            )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r[0],
                    "name": r[1],
                    "enabled": bool(r[2]),
                    "query": r[3],
                    "mode": r[4],
                    "source_type": r[5],
                    "scope": r[6],
                    "cooldown_sec": r[7],
                    "webhook_url": r[8],
                    "email_to": r[9],
                    "log_dir": r[10] if len(r) > 10 else None,
                    "file_glob": r[11] if len(r) > 11 else None,
                }
            )
        return out

    def upsert_alert_rule(self, rule: dict[str, Any]) -> str:
        rid = rule.get("id") or uuid.uuid4().hex[:12]
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT INTO alert_rules (id, name, enabled, query, mode, source_type, scope,
                   cooldown_sec, webhook_url, email_to, log_dir, file_glob, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, enabled=excluded.enabled, query=excluded.query,
                     mode=excluded.mode, source_type=excluded.source_type, scope=excluded.scope,
                     cooldown_sec=excluded.cooldown_sec, webhook_url=excluded.webhook_url,
                     email_to=excluded.email_to, log_dir=excluded.log_dir, file_glob=excluded.file_glob,
                     updated_at=excluded.updated_at""",
                (
                    rid,
                    rule["name"],
                    1 if rule.get("enabled", True) else 0,
                    rule["query"],
                    rule.get("mode", "text"),
                    rule.get("source_type"),
                    rule.get("scope", "all"),
                    int(rule.get("cooldown_sec", 300)),
                    rule.get("webhook_url"),
                    rule.get("email_to"),
                    rule.get("log_dir"),
                    rule.get("file_glob"),
                    now,
                    now,
                ),
            )
            self._conn.commit()
        return rid

    def delete_alert_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            self._conn.commit()
            return (cur.rowcount or 0) > 0

    def insert_alert_event(
        self,
        *,
        rule_id: str | None,
        source: str,
        line: str,
        ts: float,
        delivered: bool,
        payload: dict[str, Any] | None = None,
        origin: str = "hub",
        channel: str | None = None,
        status: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO alert_events (rule_id, source, line, ts, delivered, payload_json, origin,
                   channel, status, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule_id,
                    source,
                    line,
                    ts,
                    1 if delivered else 0,
                    json.dumps(payload) if payload else None,
                    origin,
                    channel,
                    status,
                    error,
                ),
            )
            self._conn.commit()

    def list_alert_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, rule_id, source, line, ts, delivered, payload_json, origin
                   FROM alert_events ORDER BY ts DESC LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r[0],
                    "rule_id": r[1],
                    "source": r[2],
                    "line": r[3],
                    "ts": r[4],
                    "delivered": bool(r[5]),
                    "payload": json.loads(r[6]) if r[6] else None,
                    "origin": r[7],
                }
            )
        return out


def importance_for_event(ev: LogEvent) -> str:
    msg = (ev.message or "").lower()
    action = (ev.action or "").lower()
    if action in ("deny", "drop", "block", "reset-both", "reset-client", "reset-server"):
        return "error"
    if ev.log_type == "THREAT":
        return "critical"
    if any(k in msg for k in ("critical", "fatal", "emerg")):
        return "critical"
    if any(k in msg for k in ("error", "fail", "denied", "blocked")):
        return "error"
    if any(k in msg for k in ("warn", "warning")):
        return "warning"
    if ev.llm_severity in ("critical", "high"):
        return "error"
    if ev.llm_severity == "medium":
        return "warning"
    return "info"


def to_stream_event(ev: LogEvent) -> StreamEvent:
    return StreamEvent(
        id=ev.id or 0,
        received_at=ev.received_at,
        source_type=ev.source_type,
        message=ev.message[:500],
        remote_ip=ev.remote_ip,
        log_type=ev.log_type,
        action=ev.action,
        importance=importance_for_event(ev),
    )


LogStore = EventStore

__all__ = ["EventStore", "LogStore", "RawLogRow", "importance_for_event", "to_stream_event"]

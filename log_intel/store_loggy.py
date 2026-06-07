"""Loggy-compatible batch analysis + meta summary methods on EventStore."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from log_intel import hub_config as config
from log_intel.loggy_ported.pan_log import AUTO_SKIP_MODEL

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    log_ids_json TEXT NOT NULL,
    model TEXT NOT NULL,
    raw_response TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    anomalies_json TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);

CREATE TABLE IF NOT EXISTS meta_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    granularity TEXT NOT NULL,
    period_label TEXT NOT NULL,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    model TEXT NOT NULL,
    raw_response TEXT NOT NULL,
    headline TEXT NOT NULL,
    summary TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    confidence TEXT NOT NULL,
    error TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_meta_gran_created ON meta_summaries(granularity, created_at DESC);

ALTER TABLE alert_rules ADD COLUMN log_dir TEXT;
ALTER TABLE alert_rules ADD COLUMN file_glob TEXT;
ALTER TABLE alert_rules ADD COLUMN updated_at REAL;

ALTER TABLE alert_events ADD COLUMN channel TEXT;
ALTER TABLE alert_events ADD COLUMN status TEXT;
ALTER TABLE alert_events ADD COLUMN error TEXT;
"""


@dataclass
class RawLogRow:
    id: int
    received_at: float
    remote_ip: str
    transport: str
    message: str


def migrate_schema_v2(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            log_ids_json TEXT NOT NULL,
            model TEXT NOT NULL,
            raw_response TEXT NOT NULL,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            anomalies_json TEXT NOT NULL,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
        CREATE TABLE IF NOT EXISTS meta_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            granularity TEXT NOT NULL,
            period_label TEXT NOT NULL,
            window_start REAL NOT NULL,
            window_end REAL NOT NULL,
            model TEXT NOT NULL,
            raw_response TEXT NOT NULL,
            headline TEXT NOT NULL,
            summary TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            confidence TEXT NOT NULL,
            error TEXT,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_meta_gran_created ON meta_summaries(granularity, created_at DESC);
        """
    )
    for col, ddl in (
        ("log_dir", "ALTER TABLE alert_rules ADD COLUMN log_dir TEXT"),
        ("file_glob", "ALTER TABLE alert_rules ADD COLUMN file_glob TEXT"),
        ("updated_at", "ALTER TABLE alert_rules ADD COLUMN updated_at REAL"),
        ("channel", "ALTER TABLE alert_events ADD COLUMN channel TEXT"),
        ("status", "ALTER TABLE alert_events ADD COLUMN status TEXT"),
        ("error", "ALTER TABLE alert_events ADD COLUMN error TEXT"),
    ):
        try:
            conn.execute(ddl)
        except sqlite3.OperationalError:
            pass


def _row_to_raw(row: tuple) -> RawLogRow:
    return RawLogRow(
        id=int(row[0]),
        received_at=float(row[1]),
        remote_ip=str(row[2] or ""),
        transport=str(row[3] or "udp"),
        message=str(row[4] or ""),
    )


class LogStoreMixin:
    def fetch_unanalyzed_batch(self, limit: int) -> list[RawLogRow]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, received_at, remote_ip, transport, message FROM events
                   WHERE analyzed_at IS NULL ORDER BY id ASC LIMIT ?""",
                (limit,),
            )
            return [_row_to_raw(r) for r in cur.fetchall()]

    def fetch_unanalyzed_in_range(
        self, since_ts: float, until_ts: float | None, limit: int
    ) -> list[RawLogRow]:
        end = until_ts if until_ts is not None else time.time()
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, received_at, remote_ip, transport, message FROM events
                   WHERE analyzed_at IS NULL AND received_at >= ? AND received_at <= ?
                   ORDER BY id ASC LIMIT ?""",
                (since_ts, end, limit),
            )
            return [_row_to_raw(r) for r in cur.fetchall()]

    def count_unanalyzed_in_range(self, since_ts: float, until_ts: float | None) -> int:
        end = until_ts if until_ts is not None else time.time()
        with self._lock:
            cur = self._conn.execute(
                """SELECT COUNT(*) FROM events
                   WHERE analyzed_at IS NULL AND received_at >= ? AND received_at <= ?""",
                (since_ts, end),
            )
            return int(cur.fetchone()[0])

    def counts_in_window(self, since_ts: float, until_ts: float | None = None) -> dict[str, int]:
        end = until_ts if until_ts is not None else time.time()
        with self._lock:
            n_raw = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ?",
                (since_ts, end),
            ).fetchone()[0]
            n_ana = self._conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE created_at >= ? AND created_at <= ?",
                (since_ts, end),
            ).fetchone()[0]
        return {"raw_in_window": int(n_raw), "analyses_in_window": int(n_ana)}

    def analysis_calendar_coverage(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(DISTINCT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch'))),
                       MIN(strftime('%Y-%m-%d', datetime(created_at, 'unixepoch'))),
                       MAX(strftime('%Y-%m-%d', datetime(created_at, 'unixepoch')))
                FROM analyses WHERE error IS NULL
                """
            ).fetchone()
        days = int(row[0] or 0) if row else 0
        return {
            "distinct_days": days,
            "oldest_day": row[1] if row else None,
            "newest_day": row[2] if row else None,
        }

    def insert_analysis(
        self,
        log_ids: list[int],
        model: str,
        raw_response: str,
        severity: str,
        summary: str,
        anomalies: list[dict[str, Any]],
        error: str | None,
    ) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO analyses (
                    created_at, log_ids_json, model, raw_response,
                    severity, summary, anomalies_json, error
                ) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    now,
                    json.dumps(log_ids),
                    model,
                    raw_response,
                    severity,
                    summary,
                    json.dumps(anomalies),
                    error,
                ),
            )
            aid = int(cur.lastrowid)
            if error is None:
                for eid in log_ids:
                    self._conn.execute(
                        """UPDATE events SET analyzed_at = ?, llm_severity = ?, llm_summary = ?, analysis_id = ?
                           WHERE id = ?""",
                        (now, severity, summary[:500], aid, eid),
                    )
            self._conn.execute(
                "DELETE FROM analyses WHERE id NOT IN (SELECT id FROM analyses ORDER BY id DESC LIMIT ?)",
                (getattr(config, "MAX_ANALYSES", 5000),),
            )
            self._conn.commit()
            return aid

    def recent_analyses(
        self,
        limit: int = 50,
        since_ts: float | None = None,
        until_ts: float | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            if since_ts is not None and until_ts is not None:
                cur = self._conn.execute(
                    """SELECT id, created_at, severity, summary, anomalies_json, error, model, log_ids_json
                       FROM analyses WHERE created_at >= ? AND created_at <= ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (since_ts, until_ts, limit),
                )
            elif since_ts is not None:
                cur = self._conn.execute(
                    """SELECT id, created_at, severity, summary, anomalies_json, error, model, log_ids_json
                       FROM analyses WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?""",
                    (since_ts, limit),
                )
            else:
                cur = self._conn.execute(
                    """SELECT id, created_at, severity, summary, anomalies_json, error, model, log_ids_json
                       FROM analyses ORDER BY created_at DESC LIMIT ?""",
                    (limit,),
                )
            rows = cur.fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r[0],
                    "created_at": r[1],
                    "severity": r[2],
                    "summary": r[3],
                    "anomalies": json.loads(r[4]) if r[4] else [],
                    "error": r[5],
                    "model": r[6],
                    "log_ids": json.loads(r[7]) if r[7] else [],
                }
            )
        return out

    def analysis_window_stats(self, start_ts: float, end_ts: float) -> dict[str, Any]:
        with self._lock:
            try:
                row = self._conn.execute(
                    """
                    SELECT COUNT(*) AS analyses_total,
                           SUM(CASE WHEN error IS NULL THEN 1 ELSE 0 END) AS ok_total,
                           SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) AS err_total,
                           SUM(CASE WHEN error IS NULL AND lower(severity) = 'high' THEN 1 ELSE 0 END) AS sev_high,
                           SUM(CASE WHEN error IS NULL AND lower(severity) = 'critical' THEN 1 ELSE 0 END) AS sev_critical,
                           COALESCE(SUM(CASE WHEN error IS NULL THEN json_array_length(anomalies_json) ELSE 0 END), 0) AS anomalies_total
                    FROM analyses WHERE created_at >= ? AND created_at <= ?
                    """,
                    (start_ts, end_ts),
                ).fetchone()
            except sqlite3.OperationalError:
                return {"analyses_total": 0, "ok_total": 0, "err_total": 0, "elevated_total": 0, "anomalies_total": 0}
        sh = int(row[3] or 0) if row else 0
        sc = int(row[4] or 0) if row else 0
        return {
            "analyses_total": int(row[0] or 0) if row else 0,
            "ok_total": int(row[1] or 0) if row else 0,
            "err_total": int(row[2] or 0) if row else 0,
            "sev_high": sh,
            "sev_critical": sc,
            "elevated_total": sh + sc,
            "anomalies_total": int(row[5] or 0) if row else 0,
        }

    def analyses_for_meta_window(self, start_ts: float, end_ts: float, limit: int) -> list[dict[str, Any]]:
        lim = max(1, min(500, int(limit)))
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, created_at, severity, summary, error, anomalies_json
                   FROM analyses WHERE created_at >= ? AND created_at <= ? AND model != ?
                   ORDER BY id ASC LIMIT ?""",
                (start_ts, end_ts, AUTO_SKIP_MODEL, lim),
            )
            return [
                {
                    "id": r[0],
                    "created_at": r[1],
                    "severity": r[2],
                    "summary": r[3],
                    "error": r[4],
                    "anomalies_json": r[5],
                }
                for r in cur.fetchall()
            ]

    def count_analyses_between(self, start_ts: float, end_ts: float) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE created_at >= ? AND created_at <= ? AND model != ?",
                (start_ts, end_ts, AUTO_SKIP_MODEL),
            )
            return int(cur.fetchone()[0])

    def insert_meta_summary(
        self,
        granularity: str,
        period_label: str,
        window_start: float,
        window_end: float,
        model: str,
        raw_response: str,
        headline: str,
        summary: str,
        findings: list[dict[str, Any]],
        confidence: str,
        error: str | None,
    ) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO meta_summaries (
                    granularity, period_label, window_start, window_end, model,
                    raw_response, headline, summary, findings_json, confidence, error, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    granularity,
                    period_label,
                    window_start,
                    window_end,
                    model,
                    raw_response,
                    headline,
                    summary,
                    json.dumps(findings),
                    confidence,
                    error,
                    now,
                ),
            )
            mid = int(cur.lastrowid)
            self._conn.execute(
                "DELETE FROM meta_summaries WHERE id NOT IN (SELECT id FROM meta_summaries ORDER BY id DESC LIMIT ?)",
                (config.MAX_META_SUMMARIES,),
            )
            self._conn.commit()
            return mid

    def meta_attempt_timestamps(self, granularity: str) -> tuple[float | None, float | None]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT
                    (SELECT MAX(created_at) FROM meta_summaries WHERE granularity = ? AND error IS NULL),
                    (SELECT MAX(created_at) FROM meta_summaries WHERE granularity = ?)
                """,
                (granularity, granularity),
            )
            row = cur.fetchone()
        if not row:
            return None, None
        return (float(row[0]) if row[0] else None, float(row[1]) if row[1] else None)

    def recent_meta_summaries(self, granularity: str, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                """SELECT id, granularity, period_label, window_start, window_end, headline, summary,
                          findings_json, confidence, error, created_at
                   FROM meta_summaries WHERE granularity = ? AND error IS NULL
                   ORDER BY created_at DESC LIMIT ?""",
                (granularity, limit),
            )
            rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "granularity": r[1],
                "period_label": r[2],
                "window_start": r[3],
                "window_end": r[4],
                "headline": r[5],
                "summary": r[6],
                "findings": json.loads(r[7]) if r[7] else [],
                "confidence": r[8],
                "error": r[9],
                "created_at": r[10],
            }
            for r in rows
        ]

    def daily_analysis_trend(self, lookback_days: int = 42) -> list[dict[str, Any]]:
        lb = max(1, min(120, int(lookback_days)))
        mod = f"-{lb} days"
        with self._lock:
            try:
                rows = self._conn.execute(
                    """
                    SELECT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch')) AS day,
                           COUNT(*) AS analyses_total,
                           SUM(CASE WHEN error IS NULL THEN 1 ELSE 0 END) AS ok_total,
                           SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) AS err_total,
                           SUM(CASE WHEN error IS NULL AND lower(severity) IN ('high','critical') THEN 1 ELSE 0 END) AS elevated_total,
                           COALESCE(SUM(CASE WHEN error IS NULL THEN json_array_length(anomalies_json) ELSE 0 END), 0) AS anomalies_total
                    FROM analyses WHERE datetime(created_at, 'unixepoch') >= date('now', ?)
                    GROUP BY day ORDER BY day ASC
                    """,
                    (mod,),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = self._conn.execute(
                    """
                    SELECT strftime('%Y-%m-%d', datetime(created_at, 'unixepoch')) AS day,
                           COUNT(*) AS analyses_total,
                           SUM(CASE WHEN error IS NULL THEN 1 ELSE 0 END) AS ok_total,
                           SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) AS err_total,
                           0 AS elevated_total, 0 AS anomalies_total
                    FROM analyses WHERE datetime(created_at, 'unixepoch') >= date('now', ?)
                    GROUP BY day ORDER BY day ASC
                    """,
                    (mod,),
                ).fetchall()
        return [
            {
                "day": str(r[0]),
                "analyses_total": int(r[1] or 0),
                "ok_total": int(r[2] or 0),
                "err_total": int(r[3] or 0),
                "elevated_total": int(r[4] or 0),
                "anomalies_total": int(r[5] or 0),
                "sev_info": 0,
                "sev_low": 0,
                "sev_medium": 0,
                "sev_high": 0,
                "sev_critical": 0,
            }
            for r in rows
        ]

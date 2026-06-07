"""Read-only adapter for loggy.db (migration archive)."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from log_intel.config import get_settings
from log_intel.models import LogEvent
from log_intel.sources_registry import adapter_source, resolve_env_path

log = logging.getLogger(__name__)


class LoggyReader:
    def __init__(self, db_path: str | None = None) -> None:
        settings = get_settings()
        src = adapter_source("loggy")
        env_path = resolve_env_path(src.db_path_env if src else "LOGGY_DB_PATH")
        self._path = db_path or env_path or settings.loggy_db_path

    @property
    def available(self) -> bool:
        return bool(self._path) and Path(self._path).is_file()

    def health(self) -> dict[str, Any]:
        if not self.available:
            return {"ok": False, "error": "loggy.db not configured or missing"}
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
            cur = conn.execute("SELECT COUNT(*) FROM raw_logs")
            count = cur.fetchone()[0]
            conn.close()
            return {"ok": True, "raw_log_count": count}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_raw_logs(
        self,
        *,
        since_id: int = 0,
        limit: int = 200,
    ) -> list[LogEvent]:
        if not self.available:
            return []
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
            cur = conn.execute(
                """SELECT id, received_at, remote_ip, transport, message
                   FROM raw_logs WHERE id > ? ORDER BY id ASC LIMIT ?""",
                (since_id, limit),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception as e:
            log.warning("loggy read failed: %s", e)
            return []

        out: list[LogEvent] = []
        for rid, received_at, remote_ip, transport, message in rows:
            out.append(
                LogEvent(
                    id=-rid,
                    received_at=float(received_at),
                    source_type="imported",
                    source_id="loggy",
                    remote_ip=remote_ip or "",
                    transport=transport or "udp",
                    raw=message or "",
                    message=message or "",
                    parser="loggy_import",
                )
            )
        return out

    def search(
        self,
        query: str,
        *,
        since: float | None = None,
        limit: int = 200,
    ) -> list[LogEvent]:
        if not self.available or not query.strip():
            return []
        since = since or 0.0
        pattern = f"%{query.strip()}%"
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
            cur = conn.execute(
                """SELECT id, received_at, remote_ip, transport, message
                   FROM raw_logs
                   WHERE received_at >= ? AND message LIKE ?
                   ORDER BY received_at DESC LIMIT ?""",
                (since, pattern, limit),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception as e:
            log.warning("loggy search failed: %s", e)
            return []

        out: list[LogEvent] = []
        for rid, received_at, remote_ip, transport, message in rows:
            out.append(
                LogEvent(
                    id=-rid,
                    received_at=float(received_at),
                    source_type="imported",
                    source_id="loggy",
                    remote_ip=remote_ip or "",
                    transport=transport or "udp",
                    raw=message or "",
                    message=message or "",
                    parser="loggy_import",
                )
            )
        return out

    def fetch_analyses(self, *, since_ts: float = 0, limit: int = 50) -> list[dict[str, Any]]:
        if not self.available:
            return []
        try:
            conn = sqlite3.connect(f"file:{self._path}?mode=ro", uri=True)
            cur = conn.execute(
                """SELECT id, created_at, severity, summary, anomalies_json, error
                   FROM analyses WHERE created_at > ? AND error IS NULL
                   ORDER BY created_at DESC LIMIT ?""",
                (since_ts, limit),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception as e:
            log.warning("loggy analyses read failed: %s", e)
            return []
        return [
            {
                "id": r[0],
                "created_at": r[1],
                "severity": r[2],
                "summary": r[3],
                "anomalies": json.loads(r[4]) if r[4] else [],
                "source": "loggy",
            }
            for r in rows
        ]

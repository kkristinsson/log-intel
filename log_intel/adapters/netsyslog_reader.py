"""Read-only adapter for netsyslog (SQLite + HTTP API)."""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

from log_intel.config import get_settings

log = logging.getLogger(__name__)


class NetsyslogReader:
    def __init__(
        self,
        db_path: str | None = None,
        api_url: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        settings = get_settings()
        self._db_path = db_path or settings.netsyslog_db_path
        self._api_url = (api_url or settings.netsyslog_api_url).rstrip("/")
        self._timeout = timeout

    @property
    def db_available(self) -> bool:
        return bool(self._db_path) and Path(self._db_path).is_file()

    def health(self) -> dict[str, Any]:
        api_ok = False
        api_err = ""
        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(f"{self._api_url}/health")
                r.raise_for_status()
                api_ok = True
        except Exception as e:
            api_err = str(e)
        db_ok = self.db_available
        return {
            "ok": api_ok or db_ok,
            "api_ok": api_ok,
            "api_error": api_err,
            "db_ok": db_ok,
        }

    def fetch_flows_api(self, hours: float = 24, limit: int = 2000) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(
                    f"{self._api_url}/api/flows",
                    params={"hours": hours, "limit": limit},
                )
                r.raise_for_status()
                return r.json()
        except Exception as e:
            log.warning("netsyslog API flows failed: %s", e)
            return {"edges": [], "error": str(e)}

    def fetch_flow_aggregates(
        self,
        hours: float = 24,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        if self.db_available:
            since = time.time() - hours * 3600
            try:
                conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
                cur = conn.execute(
                    """
                    SELECT src_ip, dst_ip, COUNT(*) AS cnt,
                           SUM(COALESCE(bytes,0)) AS sum_bytes,
                           MAX(src_lat) AS src_lat, MAX(src_lon) AS src_lon,
                           MAX(src_country) AS src_country,
                           MAX(dst_lat) AS dst_lat, MAX(dst_lon) AS dst_lon,
                           MAX(dst_country) AS dst_country
                    FROM flows WHERE ts >= ?
                    GROUP BY src_ip, dst_ip
                    HAVING src_lat IS NOT NULL AND dst_lat IS NOT NULL
                    ORDER BY cnt DESC LIMIT ?
                    """,
                    (since, limit),
                )
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, r)) for r in cur.fetchall()]
                conn.close()
                return rows
            except Exception as e:
                log.warning("netsyslog DB flows failed: %s", e)
        data = self.fetch_flows_api(hours=hours, limit=limit)
        return data.get("edges") or []

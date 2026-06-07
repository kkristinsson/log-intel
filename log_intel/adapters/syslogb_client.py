"""Read-only HTTP client for syslogb (no syslogb code changes)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from log_intel.config import get_settings

log = logging.getLogger(__name__)


class SyslogbClient:
    def __init__(self, base_url: str | None = None, timeout: float = 10.0) -> None:
        settings = get_settings()
        self._base = (base_url or settings.syslogb_base_url).rstrip("/")
        self._timeout = timeout

    def health(self) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(f"{self._base}/api/health")
                r.raise_for_status()
                return {"ok": True, "data": r.json()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def search(
        self,
        q: str,
        *,
        mode: str = "text",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(
                    f"{self._base}/api/search",
                    params={"q": q, "mode": mode, "order": "desc"},
                )
                r.raise_for_status()
                data = r.json()
                events = data.get("events") or []
                return events[:limit]
        except Exception as e:
            log.warning("syslogb search failed: %s", e)
            return []

    def request_analyze(self, path: str, scope: str = "window", window: str = "1h") -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            r = client.post(
                f"{self._base}/api/analyze",
                json={"path": path, "scope": scope, "window": window},
            )
            r.raise_for_status()
            return r.json()

    def get_analyze_job(self, job_id: str) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            r = client.get(f"{self._base}/api/analyze/{job_id}")
            r.raise_for_status()
            return r.json()

"""Juniper Mist cloud API client (events ingest)."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.eu.mist.com/api/v1"


class MistClient:
    def __init__(
        self,
        api_token: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Token {api_token.strip()}",
            "Content-Type": "application/json",
        }
        self._timeout = timeout

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> httpx.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(url, headers=self._headers, params=params)

    @staticmethod
    def _unwrap_list(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if not isinstance(data, dict):
            return []
        for key in ("results", "events", "logs", "entries", "items", "data"):
            val = data.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
        return [data]

    def get_org_id(self) -> str:
        response = self._get("self")
        response.raise_for_status()
        org_info = response.json()
        privileges = org_info.get("privileges") or []
        if not privileges:
            raise RuntimeError("No organizations found for this Mist API token")
        org_id = privileges[0].get("org_id")
        if not org_id:
            raise RuntimeError("Mist /self response missing org_id")
        return str(org_id)

    def health(self, org_id: str | None = None) -> dict[str, Any]:
        try:
            resolved_org = org_id or self.get_org_id()
            return {"ok": True, "org_id": resolved_org, "error": ""}
        except Exception as e:
            return {"ok": False, "org_id": org_id or "", "error": str(e)}

    def _events_search(self, endpoint: str, start: int, end: int, limit: int) -> list[dict[str, Any]]:
        params = {"limit": limit, "start": start, "end": end}
        response = self._get(endpoint, params=params)
        if response.status_code != 200:
            return []
        return self._unwrap_list(response.json())

    def _first_success(
        self,
        endpoints: list[str],
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        for endpoint in endpoints:
            response = self._get(endpoint, params=params)
            if response.status_code != 200:
                continue
            rows = self._unwrap_list(response.json())
            if rows:
                return rows[:limit] if limit is not None else rows
        return []

    def fetch_events(
        self,
        org_id: str,
        *,
        lookback_hours: float = 24.0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch recent Mist org events using the same fallback chain as mist-api."""
        end_sec = int(time.time())
        start_sec = end_sec - int(lookback_hours * 3600)
        end_ms = end_sec * 1000
        start_ms = start_sec * 1000

        results = self._events_search(f"orgs/{org_id}/events/search", start_ms, end_ms, limit)
        if not results:
            results = self._events_search(f"orgs/{org_id}/events/search", start_sec, end_sec, limit)
        if results:
            return results[:limit]

        params = {"limit": limit, "start": start_sec, "end": end_sec}
        results = self._first_success(
            [
                f"orgs/{org_id}/devices/events/search",
                f"orgs/{org_id}/clients/events/search",
                f"orgs/{org_id}/call/events/search",
                f"orgs/{org_id}/logs",
            ],
            params=params,
            limit=limit,
        )
        if results:
            return results

        return self._first_success(
            [
                f"orgs/{org_id}/events",
                f"orgs/{org_id}/insights/events",
                f"orgs/{org_id}/alarms",
            ],
            params=params,
            limit=limit,
        )

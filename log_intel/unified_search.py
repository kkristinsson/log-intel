"""Cross-source search: hub SQLite + syslogb files/journal + loggy archive."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.store import EventStore
from log_intel.syslogb.app.search import search_highlight_terms, search_logs

SearchMode = Literal["text", "regex"]


@dataclass
class UnifiedSearchResult:
    query: str
    mode: str
    order: str
    limit: int
    count: int
    counts_by_origin: dict[str, int] = field(default_factory=dict)
    highlight_terms: list[str] = field(default_factory=list)
    errors: dict[str, str | None] = field(default_factory=dict)
    results: list[dict[str, Any]] = field(default_factory=list)


def _normalize_hub(ev_dict: dict[str, Any]) -> dict[str, Any]:
    return {
        "origin": "hub",
        "received_at": ev_dict.get("received_at") or ev_dict.get("event_ts"),
        "message": ev_dict.get("message") or ev_dict.get("raw"),
        **ev_dict,
    }


def _normalize_syslogb(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "origin": "files",
        "received_at": ev.get("received_at") or ev.get("ts"),
        "line": ev.get("line"),
        "message": ev.get("line"),
        "source": ev.get("source"),
        "journal": ev.get("journal", False),
        "severity": ev.get("severity"),
        **{k: v for k, v in ev.items() if k not in ("line",)},
    }


def _normalize_loggy(ev_dict: dict[str, Any]) -> dict[str, Any]:
    return {
        "origin": "loggy",
        "received_at": ev_dict.get("received_at"),
        "message": ev_dict.get("message") or ev_dict.get("raw"),
        **ev_dict,
    }


def unified_search(
    store: EventStore,
    loggy: LoggyReader,
    query: str,
    *,
    mode: SearchMode = "text",
    hours: float = 168,
    limit: int = 200,
    order: str = "desc",
    importance_min: str | None = None,
    include_hub: bool = True,
    include_syslogb: bool = False,
    include_loggy: bool = False,
    source_type: str | None = None,
) -> UnifiedSearchResult:
    q = query.strip()
    if not q:
        return UnifiedSearchResult(q, mode, order, limit, 0)

    since = time.time() - hours * 3600
    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    errors: dict[str, str | None] = {"hub": None, "files": None, "loggy": None}
    num_sources = sum([include_hub, include_syslogb, include_loggy]) or 1
    per_source = max(limit // num_sources, 1)

    if include_hub:
        try:
            hub_events = store.search(q, since=since, mode=mode, limit=per_source)
            if source_type:
                hub_events = [e for e in hub_events if e.source_type == source_type]
            for ev in hub_events:
                results.append(_normalize_hub(ev.to_dict()))
            counts["hub"] = len(hub_events)
        except Exception as e:
            errors["hub"] = str(e)

    if include_syslogb:
        try:
            events, err = search_logs(
                q,
                mode,
                order=order,
                limit=per_source,
                importance_min=importance_min,
            )
            if err:
                errors["files"] = err
            else:
                for ev in events:
                    results.append(_normalize_syslogb(ev))
                counts["files"] = len(events)
        except Exception as e:
            errors["files"] = str(e)

    if include_loggy:
        try:
            loggy_events = loggy.search(q, since=since, limit=per_source)
            for ev in loggy_events:
                results.append(_normalize_loggy(ev.to_dict()))
            counts["loggy"] = len(loggy_events)
        except Exception as e:
            errors["loggy"] = str(e)

    reverse = order != "asc"
    results.sort(key=lambda r: float(r.get("received_at") or 0), reverse=reverse)
    results = results[:limit]

    terms: list[str] = []
    if mode == "text":
        try:
            terms = search_highlight_terms(q, mode)
        except ValueError:
            terms = []

    return UnifiedSearchResult(
        query=q,
        mode=mode,
        order=order,
        limit=limit,
        count=len(results),
        counts_by_origin=counts,
        highlight_terms=terms,
        errors=errors,
        results=results,
    )

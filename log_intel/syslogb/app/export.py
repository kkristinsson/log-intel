from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterator

from log_intel.syslogb.app import config
from log_intel.syslogb.app.columnizers import enrich_event, resolve_columnizer
from log_intel.syslogb.app.file_reader import recent_lines
from log_intel.syslogb.app.journal_reader import read_journal_file_page
from log_intel.syslogb.app.journal_source import is_journal_source
from log_intel.syslogb.app.search import search_logs
from log_intel.syslogb.app.store import AppStore


def _cap(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    limit = config.EXPORT_MAX_ROWS
    if len(events) > limit:
        return events[:limit]
    return events


def collect_search_events(
    query: str,
    mode: str,
    *,
    path=None,
    log_dir=None,
    localhost_only: bool = False,
    order: str = "desc",
    store: AppStore | None = None,
) -> list[dict[str, Any]]:
    events, err = search_logs(
        query,
        mode,
        path=path,
        log_dir=log_dir,
        localhost_only=localhost_only,
        order=order,
    )
    if err:
        raise ValueError(err)
    return _enrich_all(events, store)


def collect_file_events(
    path,
    *,
    failures_only: bool = False,
    order: str = "desc",
    store: AppStore | None = None,
) -> list[dict[str, Any]]:
    path_str = str(path)
    if is_journal_source(path_str):
        page, err = read_journal_file_page(path_str, direction="tail", failures_only=failures_only)
        if err:
            raise ValueError(err)
        events = page.get("events", [])
    else:
        events, err = recent_lines(path, failures_only=failures_only)
        if err:
            raise ValueError(err)
    reverse = order != "asc"
    events.sort(key=lambda e: e["received_at"], reverse=reverse)
    return _enrich_all(_cap(events), store)


def _enrich_all(events: list[dict[str, Any]], store: AppStore | None) -> list[dict[str, Any]]:
    columnizers = store.list_columnizers() if store else []
    out = []
    for ev in events:
        src = ev.get("source", "")
        col = resolve_columnizer(src, columnizers)
        out.append(enrich_event(ev, col))
    return _cap(out)


def stream_txt(events: list[dict[str, Any]]) -> Iterator[str]:
    for ev in events:
        yield ev.get("line", "") + "\n"


def stream_jsonl(events: list[dict[str, Any]]) -> Iterator[str]:
    for ev in events:
        yield json.dumps(ev, ensure_ascii=False) + "\n"


def stream_csv(events: list[dict[str, Any]]) -> Iterator[str]:
    buf = io.StringIO()
    base_fields = ["timestamp", "source", "line"]
    col_keys: list[str] = []
    for ev in events:
        cols = ev.get("columns") or {}
        for k in cols:
            if k not in col_keys:
                col_keys.append(k)
    fields = base_fields + col_keys
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    yield buf.getvalue()
    buf.seek(0)
    buf.truncate(0)
    for ev in events:
        row = {
            "timestamp": ev.get("ts"),
            "source": ev.get("source", ""),
            "line": ev.get("line", ""),
        }
        row.update(ev.get("columns") or {})
        writer.writerow(row)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

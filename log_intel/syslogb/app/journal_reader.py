"""Paged reads from systemd journal (journalctl)."""

from __future__ import annotations

import time
from typing import Any

from log_intel.syslogb.app import config
from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.journal_source import JournalSpec, is_journal_source, parse_journal_uri, read_journal_lines
from log_intel.syslogb.app.parser import parse_timestamp, sort_key


def journal_meta(uri: str) -> dict[str, Any]:
    if not is_journal_source(uri):
        return {"error": "Not a journal source"}
    try:
        parse_journal_uri(uri)
    except ValueError as e:
        return {"error": str(e)}
    return {
        "path": uri,
        "file_size": 0,
        "mtime": time.time(),
        "compressed": False,
        "forward_only": True,
        "journal": True,
    }


def read_journal_page(
    uri: str,
    *,
    direction: str = "tail",
    max_lines: int | None = None,
    since_ts: float | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return events like file_reader page (newest last in list for tail UI)."""
    spec = parse_journal_uri(uri)
    max_lines = max_lines or config.JOURNAL_PAGE_LINES
    since_arg = None
    if since_ts is not None:
        since_arg = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since_ts))

    if direction in ("tail", "newer"):
        lines, err = read_journal_lines(spec, max_lines=max_lines, since=since_arg, reverse=True)
    else:
        lines, err = read_journal_lines(spec, max_lines=max_lines, reverse=False)

    if err:
        return [], err

    now = time.time()
    events: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if not line:
            continue
        ts = parse_timestamp(line, now, source=uri)
        events.append({
            "source": uri,
            "line": line,
            "ts": ts,
            "received_at": sort_key(ts, now),
            "line_index": i,
            "read_from": 0,
            "compressed": False,
            "forward_only": True,
            "failure": is_failure_line(line),
            "journal": True,
        })
    return events, None


def read_journal_file_page(
    uri: str,
    *,
    direction: str = "tail",
    failures_only: bool = False,
    since_ts: float | None = None,
) -> tuple[dict[str, Any], str | None]:
    if direction not in ("tail", "older", "newer", "forward"):
        return {}, "invalid direction"
    events, err = read_journal_page(uri, direction=direction, since_ts=since_ts)
    if err:
        return {}, err
    if failures_only:
        events = [e for e in events if e.get("failure")]
    return {
        "path": uri,
        "events": events,
        "read_from": 0,
        "read_to": 0,
        "file_size": 0,
        "compressed": False,
        "forward_only": True,
        "journal": True,
        "has_older": True,
        "has_newer": False,
    }, None

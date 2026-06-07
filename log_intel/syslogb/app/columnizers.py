from __future__ import annotations

import csv
import io
import json
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+"
    r"(?:(?P<unit>[\w./@-]+)(?:\[(?P<pid>\d+)\])?:\s+)?"
    r"(?P<msg>.*)$"
)

_SYSLOG_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?:(?P<unit>[\w./@-]+)(?:\[(?P<pid>\d+)\])?:\s+)?"
    r"(?P<msg>.*)$"
)


def parse_syslog_line(line: str) -> dict[str, str]:
    m = _SYSLOG_ISO.match(line)
    if m:
        return {
            "timestamp": m.group("ts"),
            "host": m.group("host") or "",
            "unit": m.group("unit") or "",
            "pid": m.group("pid") or "",
            "message": m.group("msg") or "",
        }
    m = _SYSLOG_RFC3164.match(line)
    if m:
        ts = f"{m.group('mon')} {m.group('day')} {m.group('time')}"
        return {
            "timestamp": ts,
            "host": m.group("host") or "",
            "unit": m.group("unit") or "",
            "pid": m.group("pid") or "",
            "message": m.group("msg") or "",
        }
    return {
        "timestamp": "",
        "host": "",
        "unit": "",
        "pid": "",
        "message": line,
    }


def parse_csv_line(line: str, config: dict[str, Any]) -> dict[str, str]:
    delimiter = config.get("delimiter", ",")
    quote = config.get("quote", '"')
    try:
        row = next(csv.reader([line], delimiter=delimiter, quotechar=quote))
    except csv.Error:
        return {"col1": line}
    return {f"col{i + 1}": (row[i] if i < len(row) else "") for i in range(max(len(row), 1))}


def parse_regex_line(line: str, config: dict[str, Any]) -> dict[str, str]:
    pattern = config.get("pattern", "")
    if not pattern:
        return {"line": line}
    try:
        m = re.search(pattern, line)
    except re.error:
        return {"line": line}
    if not m:
        return {"line": line}
    if m.groupdict():
        return {k: v or "" for k, v in m.groupdict().items()}
    return {"match": m.group(0)}


def parse_line(line: str, columnizer: dict[str, Any]) -> dict[str, str]:
    ctype = columnizer.get("type", "raw")
    cfg = columnizer.get("config") or {}
    if ctype == "syslog":
        return parse_syslog_line(line)
    if ctype == "csv":
        return parse_csv_line(line, cfg)
    if ctype == "regex":
        return parse_regex_line(line, cfg)
    return {"line": line}


def _glob_matches(name: str, glob: str) -> bool:
    for part in (glob or "*").split(","):
        pattern = part.strip()
        if pattern and fnmatch(name, pattern):
            return True
    return False


def resolve_columnizer(source: str, columnizers: list[dict[str, Any]]) -> dict[str, Any] | None:
    name = Path(source).name
    enabled = [c for c in columnizers if c.get("enabled")]
    enabled.sort(key=lambda c: c.get("priority", 0), reverse=True)
    for c in enabled:
        glob = c.get("file_glob") or "*"
        if _glob_matches(name, glob):
            return c
    return None


def enrich_event(event: dict[str, Any], columnizer: dict[str, Any] | None) -> dict[str, Any]:
    if not columnizer:
        return event
    line = event.get("line", "")
    parsed = parse_line(line, columnizer)
    out = dict(event)
    out["columns"] = parsed
    return out

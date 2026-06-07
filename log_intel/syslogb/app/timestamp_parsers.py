from __future__ import annotations

import re
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Optional

_SMS_PRI_PATTERN = re.compile(
    r"\[sms\.(?P<event_date>\d{4}-\d{2}-\d{2})\]"
    r"(?:\s*-\s+(?P<event_time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[)?"
)

_parsers_cache: list[dict[str, Any]] | None = None


def refresh_parsers_cache(parsers: list[dict[str, Any]]) -> None:
    global _parsers_cache
    _parsers_cache = [p for p in parsers if p.get("enabled")]


def get_cached_parsers() -> list[dict[str, Any]]:
    return _parsers_cache or []


def _glob_matches(name: str, glob: str) -> bool:
    for part in (glob or "*").split(","):
        pattern = part.strip()
        if pattern and fnmatch(name, pattern):
            return True
    return False


def resolve_timestamp_parser(
    source: str,
    parsers: list[dict[str, Any]],
) -> dict[str, Any] | None:
    name = Path(source).name
    enabled = [p for p in parsers if p.get("enabled")]
    enabled.sort(key=lambda p: p.get("priority", 0), reverse=True)
    for p in enabled:
        glob = p.get("file_glob") or "*"
        if _glob_matches(name, glob):
            return p
    return None


def _parse_regex_timestamp(line: str, config: dict[str, Any]) -> Optional[float]:
    pattern = config.get("pattern", "")
    if not pattern:
        return None
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None
    m = compiled.search(line)
    if not m:
        return None
    groups = m.groupdict()
    date_group = config.get("date_group", "event_date")
    date_str = groups.get(date_group)
    if not date_str:
        return None
    time_group = config.get("time_group", "event_time")
    time_str = groups.get(time_group) or config.get("time_default", "00:00:00")
    if "." in time_str:
        time_str = time_str.split(".", 1)[0]
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return None


def parse_line_timestamp(line: str, parser: dict[str, Any]) -> Optional[float]:
    ctype = parser.get("type", "regex")
    cfg = parser.get("config") or {}
    if ctype == "regex":
        return _parse_regex_timestamp(line, cfg)
    if ctype == "sms_pri":
        m = _SMS_PRI_PATTERN.search(line)
        if not m:
            return None
        date_str = m.group("event_date")
        time_str = m.group("event_time") or cfg.get("time_default", "00:00:00")
        if "." in time_str:
            time_str = time_str.split(".", 1)[0]
        try:
            dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except ValueError:
            return None
    return None


def parse_timestamp_for_source(
    line: str,
    source: str | None,
    parsers: list[dict[str, Any]],
) -> Optional[float]:
    if not source or not parsers:
        return None
    rule = resolve_timestamp_parser(source, parsers)
    if not rule:
        return None
    return parse_line_timestamp(line, rule)

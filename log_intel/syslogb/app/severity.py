from __future__ import annotations

import re
from typing import Any

# RFC5424 severity: 0=emergency .. 7=debug
_RFC5424_PRI = re.compile(r"^<(\d{1,3})>")
_SEVERITY_WORDS = re.compile(
    r"\b(emerg(?:ency)?|alert|crit(?:ical)?|err(?:or)?|warn(?:ing)?|notice|info|debug)\b",
    re.IGNORECASE,
)
_JSON_LEVEL = re.compile(r'["\']level["\']\s*:\s*["\'](\w+)["\']', re.IGNORECASE)
_FAILURE_SUBSTRINGS = re.compile(
    r"(?i)\b("
    r"fail(?:ed|ure)?|denied|timeout|refused|unreachable|"
    r"segfault|oom|authentication failure|permission denied|"
    r"connection reset|i/o error|kernel panic"
    r")\b"
)

_RANK = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "error": 4,
    "critical": 5,
    "alert": 6,
    "emergency": 7,
    "unknown": 1,
}

_ALIASES = {
    "warn": "warning",
    "err": "error",
    "crit": "critical",
    "emerg": "emergency",
    "fatal": "critical",
    "panic": "critical",
    "major": "error",
}

IMPORTANCE_MIN_CHOICES = frozenset({"warning", "error", "critical"})


def _normalize(name: str) -> str:
    key = name.lower().strip()
    return _ALIASES.get(key, key)


def classify_line(line: str) -> str:
    if not line or not line.strip():
        return "unknown"

    m = _RFC5424_PRI.match(line)
    if m:
        sev = int(m.group(1)) % 8
        return (
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        )[sev]

    jm = _JSON_LEVEL.search(line)
    if jm:
        return _normalize(jm.group(1))

    wm = _SEVERITY_WORDS.search(line)
    if wm:
        return _normalize(wm.group(1))

    if _FAILURE_SUBSTRINGS.search(line):
        return "error"

    return "unknown"


def importance_rank(line: str) -> int:
    return _RANK.get(classify_line(line), _RANK["unknown"])


def importance_min_rank(level: str) -> int:
    norm = _normalize(level)
    if norm not in IMPORTANCE_MIN_CHOICES:
        raise ValueError(f"importance_min must be one of: {', '.join(sorted(IMPORTANCE_MIN_CHOICES))}")
    return _RANK[norm]


def meets_importance_min(line: str, min_level: str | None) -> bool:
    if not min_level:
        return True
    return importance_rank(line) >= importance_min_rank(min_level)


def filter_events_by_importance(events: list[dict[str, Any]], min_level: str | None) -> list[dict[str, Any]]:
    if not min_level:
        return events
    return [e for e in events if meets_importance_min(e.get("line", ""), min_level)]

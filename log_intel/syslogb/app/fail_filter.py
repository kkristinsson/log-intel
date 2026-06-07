from __future__ import annotations

import re

_SEVERITY_WORDS = re.compile(
    r"\b(err(?:or)?|crit(?:ical)?|alert|emerg(?:ency)?|fatal|panic)\b",
    re.IGNORECASE,
)

_FAILURE_SUBSTRINGS = re.compile(
    r"(?i)\b("
    r"fail(?:ed|ure)?|denied|timeout|refused|unreachable|"
    r"segfault|oom|authentication failure|permission denied|"
    r"connection reset|i/o error|kernel panic"
    r")\b"
)

# RFC5424 priority field at start: <13>1 ...
_RFC5424_PRI = re.compile(r"^<(\d{1,3})>")


def is_failure_line(line: str) -> bool:
    if not line or not line.strip():
        return False

    m = _RFC5424_PRI.match(line)
    if m:
        pri = int(m.group(1))
        facility = pri // 8
        severity = pri - facility * 8
        if severity <= 3:
            return True

    if _SEVERITY_WORDS.search(line):
        return True

    if _FAILURE_SUBSTRINGS.search(line):
        return True

    return False

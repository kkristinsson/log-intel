from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from log_intel.syslogb.app.timestamp_parsers import get_cached_parsers, parse_timestamp_for_source

# RFC3164: "May 14 10:15:32" or with year variants
_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

# ISO / RFC5424 leading timestamp
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True)
class ParsedLine:
    line: str
    parsed_ts: Optional[float]
    received_at: float


def _parse_default_timestamp(line: str) -> Optional[float]:
    m = _ISO.match(line)
    if m:
        raw = m.group("ts").replace(" ", "T", 1)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(raw).timestamp()
        except ValueError:
            pass

    m = _RFC3164.match(line)
    if m:
        mon = _MONTHS.get(m.group("mon"))
        if mon is None:
            return None
        day = int(m.group("day"))
        t = m.group("time")
        year = datetime.now().year
        try:
            dt = datetime.strptime(f"{year} {mon} {day} {t}", "%Y %m %d %H:%M:%S")
            return dt.timestamp()
        except ValueError:
            return None

    return None


def parse_timestamp(
    line: str,
    received_at: float,
    source: str | None = None,
    parsers: list[dict[str, Any]] | None = None,
) -> Optional[float]:
    plist = parsers if parsers is not None else get_cached_parsers()
    if source and plist:
        ts = parse_timestamp_for_source(line, source, plist)
        if ts is not None:
            return ts
    return _parse_default_timestamp(line)


def sort_key(parsed_ts: Optional[float], received_at: float) -> float:
    return parsed_ts if parsed_ts is not None else received_at

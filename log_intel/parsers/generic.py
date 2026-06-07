"""Generic syslog parser — extract IP pairs from message body."""

from __future__ import annotations

import re
import time

from log_intel.models import LogEvent
from log_intel.parsers.palo_alto import RE_PRI, _parse_pri, _rfc3164_message, _rfc5424_message

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
RE_IPV6 = re.compile(
    r"(?<![:.\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![:.\w])"
)
RE_RFC5424_VERSION = re.compile(r"^<\d+>\d+\s")


def is_windows_rfc5424(raw: str) -> bool:
    return bool(RE_RFC5424_VERSION.match(raw.strip()))


def parse_generic_syslog(
    raw: str,
    peer_ip: str,
    transport: str,
    received_at: float,
    raw_limit: int,
    *,
    source_type: str = "generic",
) -> LogEvent | None:
    facility, severity = _parse_pri(raw)
    raw_t = raw if raw_limit <= 0 else raw[:raw_limit]
    msg = _rfc5424_message(raw) if is_windows_rfc5424(raw) else _rfc3164_message(raw)

    ips: list[str] = []
    ips += RE_IPV4.findall(msg)
    ips += RE_IPV6.findall(msg)
    seen: set[str] = set()
    uniq: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)

    st = "windows" if source_type == "windows" or is_windows_rfc5424(raw) else "generic"

    return LogEvent(
        received_at=received_at,
        source_type=st,
        remote_ip=peer_ip,
        transport=transport,
        raw=raw_t,
        message=msg,
        parser="generic",
        syslog_host=peer_ip,
        facility=facility,
        severity=severity,
        src_ip=uniq[0] if len(uniq) >= 1 else None,
        dst_ip=uniq[1] if len(uniq) >= 2 else None,
        event_ts=received_at,
    )

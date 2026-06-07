"""Palo Alto PAN-OS syslog CSV parser (adapted from netsyslog/loggy patterns)."""

from __future__ import annotations

import csv
import re
import time
from datetime import datetime

from log_intel.config import get_palo_indices
from log_intel.models import LogEvent

RE_PRI = re.compile(r"^<(\d{1,3})>\s*")
RE_RFC5424 = re.compile(r"^<(\d+)>(\d+)\s")
RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _parse_pri(raw: str) -> tuple[int | None, int | None]:
    m = RE_RFC5424.match(raw.strip())
    if m:
        pri = int(m.group(1))
        return pri // 8, pri % 8
    m = RE_PRI.match(raw.strip())
    if m:
        pri = int(m.group(1))
        return pri // 8, pri % 8
    return None, None


def _rfc3164_message(raw: str) -> str:
    s = raw.strip()
    m = RE_PRI.match(s)
    if m:
        s = s[m.end() :]
    parts = s.split(None, 2)
    if len(parts) >= 3:
        return parts[2].strip()
    return s


def _rfc5424_message(raw: str) -> str:
    marker = " - - - - "
    idx = raw.find(marker)
    if idx >= 0:
        return raw[idx + len(marker) :].strip()
    return _rfc3164_message(raw)


def _safe_int(val: str | None) -> int | None:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _parse_ts_from_palo(row: list[str], time_col: int = 5) -> float:
    if time_col < 0 or time_col >= len(row):
        return time.time()
    tg = row[time_col].strip()
    if not tg:
        return time.time()
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(tg[:32], fmt).timestamp()
        except ValueError:
            continue
    return time.time()


_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6", "ipv6-tcp", "ipv6-udp", "sctp"})


def _first_two_ipv4(fields: list[str]) -> tuple[str | None, str | None]:
    ips: list[str] = []
    for f in fields:
        s = f.strip()
        if RE_IPV4.match(s):
            ips.append(s)
            if len(ips) >= 2:
                break
    if len(ips) >= 2:
        return ips[0], ips[1]
    if len(ips) == 1:
        return ips[0], None
    return None, None


def _action_after_protocol(fields: list[str]) -> str | None:
    for i, field in enumerate(fields):
        if field.strip().lower() in _PROTOCOLS and i + 1 < len(fields):
            return fields[i + 1].strip().lower()
    return None


def parse_palo_alto_body(
    body: str,
    *,
    received_at: float,
    remote_ip: str,
    transport: str,
    raw: str,
    syslog_host: str = "",
) -> LogEvent | None:
    idx = get_palo_indices()
    try:
        row = next(csv.reader([body]))
    except Exception:
        return None
    need = max(idx.src, idx.dst, idx.type_col, idx.subtype) + 1
    if len(row) < need:
        return None

    def col(i: int | None) -> str | None:
        if i is None or i < 0 or i >= len(row):
            return None
        v = row[i].strip()
        return v or None

    log_type = col(idx.type_col)
    if not log_type:
        return None

    src = col(idx.src)
    dst = col(idx.dst)
    if not src or not dst or not RE_IPV4.match(src or ""):
        src, dst = _first_two_ipv4(row)
    event_ts = _parse_ts_from_palo(row, 5)
    action = _action_after_protocol(row) or (col(idx.action) or "").lower() or None

    return LogEvent(
        received_at=received_at,
        source_type="palo_alto",
        remote_ip=remote_ip,
        transport=transport,
        raw=raw,
        message=body,
        parser="palo_alto",
        syslog_host=syslog_host or remote_ip,
        log_type=log_type.upper(),
        src_ip=src,
        dst_ip=dst,
        src_port=_safe_int(col(idx.sport)),
        dst_port=_safe_int(col(idx.dport)),
        proto=col(idx.proto),
        action=action,
        event_ts=event_ts,
    )


def is_palo_alto_message(message: str) -> bool:
    if "TRAFFIC" in message or "THREAT" in message or "SYSTEM" in message:
        parts = message.split(",")
        return len(parts) > 15
    marker = " - - - - "
    if marker in message:
        payload = message[message.find(marker) + len(marker) :]
        return "TRAFFIC" in payload or "THREAT" in payload or "SYSTEM" in payload
    return False


def parse_palo_alto_syslog(
    raw: str,
    peer_ip: str,
    transport: str,
    received_at: float,
    raw_limit: int,
) -> LogEvent | None:
    facility, severity = _parse_pri(raw)
    raw_t = raw if raw_limit <= 0 else raw[:raw_limit]
    msg = _rfc5424_message(raw)
    if not is_palo_alto_message(msg):
        return None
    ev = parse_palo_alto_body(
        msg,
        received_at=received_at,
        remote_ip=peer_ip,
        transport=transport,
        raw=raw_t,
        syslog_host=peer_ip,
    )
    if ev:
        ev.facility = facility
        ev.severity = severity
    return ev

"""Classify and parse incoming syslog messages."""

from __future__ import annotations

import time

from log_intel.models import LogEvent
from log_intel.parsers.generic import is_windows_rfc5424, parse_generic_syslog
from log_intel.parsers.palo_alto import is_palo_alto_message, parse_palo_alto_syslog


def classify_and_parse(
    raw: str,
    peer_ip: str,
    transport: str,
    raw_truncate: int,
) -> LogEvent | None:
    received_at = time.time()
    msg_body = raw
    if " - - - - " in raw:
        msg_body = raw[raw.find(" - - - - ") + len(" - - - - ") :]

    if is_palo_alto_message(msg_body) or is_palo_alto_message(raw):
        ev = parse_palo_alto_syslog(raw, peer_ip, transport, received_at, raw_truncate)
        if ev is not None:
            return ev

    st = "windows" if is_windows_rfc5424(raw) else "generic"
    return parse_generic_syslog(
        raw,
        peer_ip,
        transport,
        received_at,
        raw_truncate,
        source_type=st,
    )

"""Classify and parse incoming syslog messages."""

from __future__ import annotations

import time

from log_intel.models import LogEvent
from log_intel.parsers.generic import is_windows_rfc5424, parse_generic_syslog
from log_intel.parsers.palo_alto import (
    _rfc5424_message,
    is_palo_alto_message,
    parse_palo_alto_syslog,
)
from log_intel.sources_registry import classify_source_type


def classify_and_parse(
    raw: str,
    peer_ip: str,
    transport: str,
    raw_truncate: int,
) -> LogEvent | None:
    received_at = time.time()
    msg_body = _rfc5424_message(raw) if raw.lstrip().startswith("<") else raw

    if is_palo_alto_message(msg_body) or is_palo_alto_message(raw):
        ev = parse_palo_alto_syslog(raw, peer_ip, transport, received_at, raw_truncate)
        if ev is not None:
            return ev

    hinted = classify_source_type(raw, msg_body)
    if hinted == "windows" or (hinted is None and is_windows_rfc5424(raw)):
        st = "windows"
    elif hinted:
        st = hinted
    else:
        st = "generic"
    return parse_generic_syslog(
        raw,
        peer_ip,
        transport,
        received_at,
        raw_truncate,
        source_type=st,
    )

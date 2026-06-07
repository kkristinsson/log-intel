"""Tests for log-intel parsers and classifier."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_intel.ingest.classifier import classify_and_parse
from log_intel.parsers.palo_alto import is_palo_alto_message, parse_palo_alto_syslog
from log_intel.parsers.generic import parse_generic_syslog

FIXTURE = Path(__file__).parent / "fixtures" / "pan_sample.syslog"


@pytest.fixture
def pan_lines() -> list[str]:
    if not FIXTURE.is_file():
        pytest.skip("fixture missing")
    return [ln.strip() for ln in FIXTURE.read_text().splitlines() if ln.strip()]


def test_is_palo_alto_message(pan_lines: list[str]) -> None:
    assert is_palo_alto_message(pan_lines[0])


def test_parse_palo_traffic(pan_lines: list[str]) -> None:
    ev = parse_palo_alto_syslog(pan_lines[0], "10.0.0.1", "udp", 1000.0, 2048)
    assert ev is not None
    assert ev.source_type == "palo_alto"
    assert ev.log_type == "TRAFFIC"
    assert ev.action == "deny"


def test_classify_and_parse_pan(pan_lines: list[str]) -> None:
    ev = classify_and_parse(pan_lines[0], "192.168.1.1", "udp", 2048)
    assert ev is not None
    assert ev.parser == "palo_alto"


def test_generic_syslog() -> None:
    raw = "<134>Jan  1 00:00:00 host sshd[1]: Failed password for user from 203.0.113.1 port 22"
    ev = parse_generic_syslog(raw, "10.0.0.2", "udp", 1000.0, 2048)
    assert ev is not None
    assert ev.source_type == "generic"
    assert ev.src_ip == "203.0.113.1"

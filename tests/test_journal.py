from __future__ import annotations

import os

import pytest

from log_intel.syslogb.app import config
from log_intel.syslogb.app.journal_source import (
    is_journal_source,
    list_journal_sources,
    parse_journal_uri,
)


def test_is_journal_source():
    assert is_journal_source("journal://system")
    assert is_journal_source("journal://boot")
    assert is_journal_source("journal://unit/ssh.service")
    assert not is_journal_source("/var/log/syslog")
    assert not is_journal_source("journal:/system")


def test_parse_journal_uri():
    boot = parse_journal_uri("journal://boot")
    assert boot.boot_only is True
    assert boot.name == "Current boot"

    system = parse_journal_uri("journal://system")
    assert system.boot_only is False
    assert system.name == "System journal"

    unit = parse_journal_uri("journal://unit/nginx.service")
    assert unit.uri.endswith("nginx.service")
    assert unit.name == "nginx.service"


def test_parse_journal_uri_invalid():
    with pytest.raises(ValueError):
        parse_journal_uri("/var/log/syslog")
    with pytest.raises(ValueError):
        parse_journal_uri("journal://unknown")


def test_list_journal_sources_disabled(monkeypatch):
    monkeypatch.setattr(config, "JOURNAL_ENABLED", False)
    monkeypatch.setattr(config, "JOURNAL_UNITS", "ssh.service")
    assert list_journal_sources() == []


def test_list_journal_sources_with_units(monkeypatch):
    monkeypatch.setattr(config, "JOURNAL_ENABLED", True)
    monkeypatch.setattr(config, "JOURNAL_UNITS", "ssh.service,nginx.service")
    uris = {s.uri for s in list_journal_sources()}
    assert "journal://system" in uris
    assert "journal://boot" in uris
    assert "journal://unit/ssh.service" in uris
    assert "journal://unit/nginx.service" in uris


@pytest.mark.skipif(not os.path.exists("/run/systemd/system"), reason="no systemd")
def test_journal_available_on_systemd_host():
    from log_intel.syslogb.app.journal_source import journal_available

    ok, msg = journal_available()
    assert isinstance(ok, bool)
    assert isinstance(msg, str)

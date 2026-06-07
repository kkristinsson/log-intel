"""Tests for sources.yaml registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_intel.sources_registry import (
    classify_source_type,
    load_sources,
    reload_sources,
    sources_health,
)


@pytest.fixture(autouse=True)
def clear_cache():
    reload_sources()
    yield
    reload_sources()


def test_load_sources_default_when_missing():
    reload_sources()
    sources = load_sources("/nonexistent/sources.yaml")
    ids = {s.id for s in sources}
    assert "palo_alto" in ids
    assert "generic_syslog" in ids


def test_load_sources_fixture():
    fixture = Path(__file__).parent / "fixtures" / "sources_test.yaml"
    sources = load_sources(str(fixture))
    assert len(sources) == 1
    assert sources[0].id == "test_custom"
    assert sources[0].match[0].pattern == "CUSTOM_MARKER"


def test_classify_from_match_rules(monkeypatch):
    fixture = Path(__file__).parent / "fixtures" / "sources_test.yaml"
    sources = load_sources(str(fixture))
    monkeypatch.setattr(
        "log_intel.sources_registry.load_sources",
        lambda path=None: sources,
    )
    st = classify_source_type("host msg CUSTOM_MARKER here", "CUSTOM_MARKER")
    assert st == "custom_type"


def test_sources_health():
    reload_sources()
    health = sources_health()
    assert isinstance(health, list)
    assert all("id" in h for h in health)

"""Regression tests for low-severity bugfixes."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from log_intel.config import Settings, _env_float, _env_int
from log_intel.models import LogEvent
from log_intel.parsers.palo_alto import RE_IPV4, is_palo_alto_message, parse_palo_alto_syslog
from log_intel.store import EventStore


def test_palo_ipv4_rejects_out_of_range() -> None:
    assert RE_IPV4.match("192.168.1.1")
    assert RE_IPV4.match("255.255.255.255")
    assert not RE_IPV4.match("999.1.1.1")
    assert not RE_IPV4.match("1.2.3.256")
    assert not RE_IPV4.match("not-an-ip")


def test_is_palo_alto_rejects_keyword_noise() -> None:
    # Many commas + TRAFFIC keyword but not a PAN CSV shape.
    noise = "SYSTEM note: TRAFFIC," + ",".join(f"f{i}" for i in range(20))
    assert not is_palo_alto_message(noise)


def test_is_palo_alto_accepts_fixture() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pan_sample.syslog"
    if not fixture.is_file():
        pytest.skip("fixture missing")
    raw = fixture.read_text().splitlines()[0].strip()
    assert is_palo_alto_message(raw)
    ev = parse_palo_alto_syslog(raw, "10.0.0.1", "udp", 1000.0, 2048)
    assert ev is not None
    assert ev.log_type == "TRAFFIC"


def test_env_int_float_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_INTEL_TEST_BAD_INT", "nope")
    monkeypatch.setenv("LOG_INTEL_TEST_BAD_FLOAT", "n/a")
    assert _env_int("LOG_INTEL_TEST_BAD_INT", 42) == 42
    assert _env_float("LOG_INTEL_TEST_BAD_FLOAT", 1.5) == 1.5
    monkeypatch.setenv("LOG_INTEL_TEST_OK_INT", "7")
    assert _env_int("LOG_INTEL_TEST_OK_INT", 0) == 7


def test_analysis_worker_links_real_analysis_id() -> None:
    from log_intel.analysis.worker import AnalysisWorker

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"))
        eid = store.insert(
            LogEvent(
                received_at=time.time(),
                source_type="generic",
                remote_ip="1.2.3.4",
                transport="udp",
                raw="err",
                message="error failed",
                parser="generic",
            )
        )
        worker = AnalysisWorker(store)
        with patch("log_intel.analysis.ollama_client.analyze_batch") as mock_llm:
            mock_llm.return_value = (
                {"severity": "high", "summary": "bad", "anomalies": []},
                '{"ok":true}',
            )
            job_id = worker.run_on_demand([eid])
            # Worker thread is daemon; wait briefly for completion.
            for _ in range(50):
                job = store.get_analysis_job(job_id)
                if job and job["status"] in ("done", "failed"):
                    break
                time.sleep(0.05)
        job = store.get_analysis_job(job_id)
        assert job is not None
        assert job["status"] == "done"
        assert job["result"]["analysis_id"] >= 1
        ev = store.get_event(eid)
        assert ev is not None
        assert ev.analysis_id == job["result"]["analysis_id"]
        store.close()


def test_prune_with_floors_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "log_intel.config.get_settings",
        lambda: Settings(reserve_events_mist=100, reserve_events_palo=100),
    )
    with tempfile.TemporaryDirectory() as td:
        store = EventStore(str(Path(td) / "t.sqlite"), max_events=10)
        for i in range(40):
            store.insert(
                LogEvent(
                    received_at=1000.0 + i,
                    source_type="mist" if i % 2 == 0 else "palo_alto",
                    remote_ip="1.1.1.1",
                    transport="udp",
                    raw=f"r{i}",
                    message=f"m{i}",
                    parser=f"mist:id-{i}" if i % 2 == 0 else f"palo:{i}",
                )
            )
        assert store.count_events() == 10
        store.close()

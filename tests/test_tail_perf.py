"""Performance-oriented tail/scanner/health behaviour."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from log_intel.syslogb.app.tailer import FileTailer
from log_intel.syslogb.app.tail_service import TailService


def test_file_tailer_skips_classify_when_unwanted() -> None:
    hits: list[str] = []
    raws: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "app.log"
        path.write_text("start\n")
        tailer = FileTailer(
            path,
            on_failure_line=lambda source, line, ts, received_at: hits.append(line),
            on_raw_line=lambda source, line, ts, received_at: raws.append(line),
            want_failures=lambda: False,
            want_raw=lambda: False,
            poll_interval_sec=0.05,
        )
        tailer.start()
        time.sleep(0.12)
        with path.open("a") as fh:
            fh.write("error failed kernel panic\n")
            fh.flush()
        time.sleep(0.25)
        tailer.stop()
    assert hits == []
    assert raws == []


def test_file_tailer_classifies_failures_when_wanted() -> None:
    hits: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "app.log"
        path.write_text("start\n")
        tailer = FileTailer(
            path,
            on_failure_line=lambda source, line, ts, received_at: hits.append(line),
            want_failures=lambda: True,
            poll_interval_sec=0.05,
        )
        tailer.start()
        time.sleep(0.12)
        with path.open("a") as fh:
            fh.write("kernel panic on cpu0\n")
            fh.flush()
        deadline = time.time() + 2.0
        while not hits and time.time() < deadline:
            time.sleep(0.05)
        tailer.stop()
    assert any("kernel panic" in line for line in hits)


def test_tail_service_want_failures_tracks_sse_clients() -> None:
    svc = TailService()
    assert svc._want_failures() is False
    q = svc.subscribe_sse()
    assert svc._want_failures() is True
    svc.unsubscribe_sse(q)
    assert svc._want_failures() is False


def test_is_probably_binary_caches_growing_text_file(tmp_path: Path) -> None:
    from log_intel.syslogb.app import scanner

    scanner._binary_cache.clear()
    path = tmp_path / "app.log"
    path.write_text("hello\n")
    opens = {"n": 0}
    real_open = open

    def counting_open(*args, **kwargs):
        target = args[0] if args else kwargs.get("file")
        if str(target) == str(path):
            opens["n"] += 1
        return real_open(*args, **kwargs)

    with patch("builtins.open", counting_open):
        assert scanner.is_probably_binary(path) is False
        first = opens["n"]
        assert first >= 1
        assert scanner.is_probably_binary(path) is False
        assert opens["n"] == first
        path.write_text("hello\nmore\n")
        assert scanner.is_probably_binary(path) is False
        assert opens["n"] == first


def test_health_check_is_cached(monkeypatch) -> None:
    from log_intel.syslogb.app import llm_client

    llm_client._health_cache = None
    calls = {"n": 0}

    monkeypatch.setattr(llm_client, "llm_enabled", lambda: True)
    monkeypatch.setattr(llm_client, "llm_provider", lambda: "ollama")
    monkeypatch.setattr(llm_client, "resolve_chat_model", lambda: "qwen3.6:27b-q8_0")
    monkeypatch.setattr(llm_client, "embed_model_name", lambda: "nomic-embed-text")

    def listed():
        calls["n"] += 1
        return ["qwen3.6:27b-q8_0", "nomic-embed-text"]

    monkeypatch.setattr(llm_client, "_ollama_listed_models", listed)
    first = llm_client.health_check()
    second = llm_client.health_check()
    assert first == second
    assert calls["n"] == 1
    llm_client.health_check(force=True)
    assert calls["n"] == 2
    llm_client._health_cache = None


def test_index_ui_has_opt_in_live_failures() -> None:
    root = Path(__file__).resolve().parents[1]
    html = (root / "log_intel/syslogb/web/templates/index.html").read_text()
    js = (root / "log_intel/syslogb/web/static/app.js").read_text()
    assert 'id="live-failures-btn"' in html
    assert "maybeConnectAllFilesStream" in js
    assert 'LIVE_FAILURES_KEY = "logIntel.liveFailures"' in js
    assert "setInterval(loadFiles, 30000)" in js
    assert "connectStream();\n  setInterval(loadFiles, 10000)" not in js


def test_index_renders_without_blocking_llm_health(tmp_path: Path) -> None:
    from log_intel.syslogb.app.alert_engine import AlertEngine
    from log_intel.syslogb.app.analyze_worker import AnalyzeWorker
    from log_intel.syslogb.app.store import AppStore
    from log_intel.syslogb.app.tail_service import TailService
    from log_intel.syslogb.web.routes import create_app

    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("ok\n")
    store = AppStore(db_path=tmp_path / "analyses.db")
    store.set_many({
        "SETUP_COMPLETE": "1",
        "AUTH_ENABLED": "0",
        "LLM_ENABLED": "0",
        "LOG_DIRS": str(logs),
        "LOG_DIR": str(logs),
        "FLASK_SECRET_KEY": "test-secret-not-for-prod",
        "LOCAL_AUTH_USERNAME": "",
        "LOCAL_AUTH_PASSWORD": "",
    })
    tail = TailService()
    worker = AnalyzeWorker(store)
    alerts = AlertEngine(store)
    app = create_app(tail, store, worker, alerts)
    app.config["TESTING"] = True
    with app.test_client() as client:
        res = client.get("/")
        assert res.status_code == 200
        body = res.get_data(as_text=True)
        assert "live-failures-btn" in body
        assert "Select a log file" in body
        assert "Connecting…" not in body

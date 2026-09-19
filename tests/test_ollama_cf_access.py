"""Cloudflare Access headers for remote Ollama."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from log_intel.ollama_http import cf_access_headers
from log_intel.syslogb.app.settings_registry import SECRET_KEYS, registry_by_key


def test_cf_access_headers_empty() -> None:
    assert cf_access_headers() == {}
    assert cf_access_headers(" ", " ") == {}


def test_cf_access_headers_set() -> None:
    assert cf_access_headers("id.access", "sekrit") == {
        "CF-Access-Client-Id": "id.access",
        "CF-Access-Client-Secret": "sekrit",
    }


def test_cf_access_keys_are_secrets() -> None:
    defs = registry_by_key()
    assert "CF_ACCESS_CLIENT_ID" in SECRET_KEYS
    assert "CF_ACCESS_CLIENT_SECRET" in SECRET_KEYS
    assert defs["CF_ACCESS_CLIENT_ID"].value_type == "secret"
    assert defs["CF_ACCESS_CLIENT_SECRET"].value_type == "secret"
    assert defs["CF_ACCESS_CLIENT_ID"].section == "llm"


def test_store_masks_cf_access_secrets(tmp_path) -> None:
    from log_intel.syslogb.app.store import AppStore

    store = AppStore(db_path=tmp_path / "analyses.db")
    store.sync_registry_settings()
    store.set_many(
        {
            "CF_ACCESS_CLIENT_ID": "324a0ef.access",
            "CF_ACCESS_CLIENT_SECRET": "temporary-secret",
            "OLLAMA_BASE_URL": "https://ollama.mpls.se",
            "LLM_PROVIDER": "ollama",
        }
    )
    assert store.get("CF_ACCESS_CLIENT_ID") == "324a0ef.access"
    grouped = store.list_settings_grouped()
    llm = {item["key"]: item for item in grouped["llm"]}
    assert llm["CF_ACCESS_CLIENT_ID"]["secret"] is True
    assert llm["CF_ACCESS_CLIENT_SECRET"]["secret"] is True
    assert llm["CF_ACCESS_CLIENT_ID"]["value"] == ""
    assert llm["CF_ACCESS_CLIENT_SECRET"]["value"] == ""
    assert llm["CF_ACCESS_CLIENT_ID"]["configured"] is True
    assert llm["OLLAMA_BASE_URL"]["value"] == "https://ollama.mpls.se"


def test_ollama_list_models_sends_cf_headers(monkeypatch) -> None:
    from log_intel.syslogb.app import config
    from log_intel.syslogb.app import llm_client

    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "https://ollama.mpls.se")
    monkeypatch.setattr(config, "CF_ACCESS_CLIENT_ID", "id.access")
    monkeypatch.setattr(config, "CF_ACCESS_CLIENT_SECRET", "sekrit")

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"models": [{"name": "qwen3.6:27b-q8_0"}]}
    mock_resp.raise_for_status.return_value = None
    with patch("log_intel.syslogb.app.llm_client.requests.get", return_value=mock_resp) as get:
        names = llm_client._ollama_listed_models()
    assert names == ["qwen3.6:27b-q8_0"]
    kwargs = get.call_args.kwargs
    assert kwargs["headers"]["CF-Access-Client-Id"] == "id.access"
    assert kwargs["headers"]["CF-Access-Client-Secret"] == "sekrit"


def test_hub_health_check_sends_cf_headers() -> None:
    from log_intel.analysis import ollama_client
    from log_intel.config import Settings

    settings = Settings(
        ollama_base_url="https://ollama.mpls.se",
        cf_access_client_id="id.access",
        cf_access_client_secret="sekrit",
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    with patch("log_intel.analysis.ollama_client.get_settings", return_value=settings):
        with patch("log_intel.analysis.ollama_client.requests.get", return_value=mock_resp) as get:
            ok, msg = ollama_client.health_check()
    assert ok
    assert "ollama.mpls.se" in msg
    assert get.call_args.kwargs["headers"]["CF-Access-Client-Id"] == "id.access"


def test_hub_analyze_batch_sends_cf_headers() -> None:
    from log_intel.analysis import ollama_client
    from log_intel.config import Settings

    settings = Settings(
        ollama_base_url="https://ollama.mpls.se",
        ollama_model="qwen3.6:27b-q8_0",
        ollama_json_format=False,
        cf_access_client_id="id.access",
        cf_access_client_secret="sekrit",
        log_line_max_chars=1200,
        ollama_timeout_sec=30,
        ollama_num_predict=256,
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "message": {
            "content": '{"severity":"info","summary":"ok","anomalies":[]}',
        }
    }
    with patch("log_intel.analysis.ollama_client.get_settings", return_value=settings):
        with patch("log_intel.analysis.ollama_client.requests.post", return_value=mock_resp) as post:
            parsed, _raw = ollama_client.analyze_batch(["sshd: session opened"])
    assert parsed["severity"] == "info"
    assert post.call_args.kwargs["headers"]["CF-Access-Client-Secret"] == "sekrit"
    assert str(post.call_args.args[0]).endswith("/api/chat")

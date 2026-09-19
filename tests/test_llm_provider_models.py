"""Chat model must follow the selected LLM provider."""

from __future__ import annotations

from log_intel.syslogb.app import config
from log_intel.syslogb.app import llm_client


def test_ollama_provider_ignores_stale_openai_chat_model(monkeypatch) -> None:
    monkeypatch.setattr(config, "LLM_PROVIDER", "ollama")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "qwen3.6:27b-q8_0")
    monkeypatch.setattr(config, "LLM_CHAT_MODEL", "gpt-oss-120b")
    monkeypatch.setattr(llm_client, "_cached_ollama_chat_model", None)
    monkeypatch.setattr(llm_client, "_cached_ollama_chat_at", 0.0)

    assert llm_client.chat_model_name() == "qwen3.6:27b-q8_0"


def test_openai_provider_uses_remote_chat_model(monkeypatch) -> None:
    monkeypatch.setattr(config, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "qwen3.6:27b-q8_0")
    monkeypatch.setattr(config, "LLM_CHAT_MODEL", "gpt-oss-120b")

    assert llm_client.chat_model_name() == "gpt-oss-120b"


def test_hybrid_provider_uses_remote_chat_model(monkeypatch) -> None:
    monkeypatch.setattr(config, "LLM_PROVIDER", "hybrid")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "qwen3.6:27b-q8_0")
    monkeypatch.setattr(config, "LLM_CHAT_MODEL", "gpt-oss-120b")

    assert llm_client.chat_model_name() == "gpt-oss-120b"

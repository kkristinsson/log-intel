"""Security helper tests."""

from __future__ import annotations

from log_intel.syslogb.app.security import validate_outbound_webhook_url


def test_validate_webhook_blocks_private_ip(monkeypatch) -> None:
    monkeypatch.delenv("LOG_INTEL_WEBHOOK_ALLOW_PRIVATE", raising=False)
    ok, err = validate_outbound_webhook_url("http://127.0.0.1:9/hook")
    assert not ok
    assert "private" in err.lower() or "internal" in err.lower()


def test_validate_webhook_allows_https_public() -> None:
    ok, err = validate_outbound_webhook_url("https://discord.com/api/webhooks/1/token")
    assert ok, err


def test_validate_webhook_empty_ok() -> None:
    ok, err = validate_outbound_webhook_url("")
    assert ok and err == ""

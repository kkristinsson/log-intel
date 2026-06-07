"""Pytest defaults for log-intel."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _allow_test_webhook_urls(monkeypatch):
    monkeypatch.setenv("LOG_INTEL_WEBHOOK_ALLOW_PRIVATE", "1")

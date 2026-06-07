"""Redirect safety tests."""

from __future__ import annotations

from flask import Flask

from log_intel.syslogb.app.security import safe_redirect_target


def test_safe_redirect_rejects_external() -> None:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    with app.test_request_context("/"):
        assert safe_redirect_target("https://evil.example/phish") == "/"
        assert safe_redirect_target("//evil.example") == "/"
        assert safe_redirect_target("/hub") == "/hub"

"""Journal window LLM pipeline tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from log_intel.syslogb.rag.pipeline import analyze_source


def test_journal_requires_window() -> None:
    with pytest.raises(ValueError, match="window"):
        analyze_source("journal://system", window=None)


@patch("log_intel.syslogb.rag.pipeline.read_journal_window")
@patch("log_intel.syslogb.rag.pipeline.analyze_lines")
def test_journal_window_analyze(mock_analyze, mock_read) -> None:
    mock_read.return_value = (["error ssh failed"], "Journal window (1h)")
    mock_analyze.return_value = (
        {"severity": "medium", "summary": "ssh issue", "anomalies": []},
        "{}",
    )
    parsed, raw, mode = analyze_source("journal://system", window="1h")
    assert parsed["severity"] == "medium"
    assert mode == "direct-journal-window"
    mock_read.assert_called_once()

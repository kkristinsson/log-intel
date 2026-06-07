"""Build text bundles for scheduled daily/weekly meta-LLM calls (bulk analysis review)."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from log_intel import hub_config as config

if TYPE_CHECKING:
    from log_intel.store import LogStore


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def _trunc(s: str, n: int) -> str:
    s = s.replace("\n", " ").strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _anomaly_n(anomalies_json: str | None, err: str | None) -> int:
    if err:
        return 0
    try:
        v = json.loads(anomalies_json or "[]")
        return len(v) if isinstance(v, list) else 0
    except json.JSONDecodeError:
        return 0


def build_daily_meta_context(store: "LogStore", start_ts: float, end_ts: float) -> str:
    stats = store.analysis_window_stats(start_ts, end_ts)
    rows = store.analyses_for_meta_window(start_ts, end_ts, config.META_CONTEXT_MAX_ANALYSES)
    lines: list[str] = [
        f"ROLE=LOGGY_DAILY_META_WINDOW UTC={_utc(start_ts)}..{_utc(end_ts)}",
        f"AGGREGATE_JSON={json.dumps(stats, separators=(',', ':'))}",
        "PER_ANALYSIS_SNIPPETS (oldest→newest in window; summaries truncated):",
    ]
    for i, r in enumerate(rows):
        err = r.get("error")
        summ = _trunc(str(r.get("summary") or ""), 320)
        sev = str(r.get("severity") or "")
        aid = int(r["id"])
        n_an = _anomaly_n(str(r.get("anomalies_json") or "[]"), str(err) if err else None)
        if err:
            lines.append(f"[{i}] id={aid} FAILED err={_trunc(str(err), 120)}")
        else:
            lines.append(f"[{i}] id={aid} sev={sev} anomalies={n_an} summary={summ}")
    lines.append(
        "TASK: Cross-batch review. Find drift, clusters, or storylines single batches miss. "
        "Ignore vendor boilerplate unless it forms a pattern."
    )
    return "\n".join(lines)


def build_weekly_meta_context(store: "LogStore", start_ts: float, end_ts: float) -> str:
    stats = store.analysis_window_stats(start_ts, end_ts)
    daily_meta = store.recent_meta_summaries("daily", limit=8)
    rows = store.analyses_for_meta_window(start_ts, end_ts, config.META_CONTEXT_MAX_ANALYSES)
    dm_lines = []
    for d in daily_meta:
        dm_lines.append(
            f"- {_utc(float(d['created_at']))} label={d.get('period_label','')} "
            f"conf={d.get('confidence','')} headline={_trunc(str(d.get('headline') or ''), 140)}"
        )
    lines: list[str] = [
        f"ROLE=LOGGY_WEEKLY_META_WINDOW UTC={_utc(start_ts)}..{_utc(end_ts)}",
        f"AGGREGATE_JSON={json.dumps(stats, separators=(',', ':'))}",
        "RECENT_DAILY_META_RUNS (newest first):",
        "\n".join(dm_lines) if dm_lines else "(none yet — still give weekly guidance from aggregates + snippets.)",
        "PER_ANALYSIS_SNIPPETS:",
    ]
    for i, r in enumerate(rows):
        err = r.get("error")
        summ = _trunc(str(r.get("summary") or ""), 280)
        sev = str(r.get("severity") or "")
        aid = int(r["id"])
        n_an = _anomaly_n(str(r.get("anomalies_json") or "[]"), str(err) if err else None)
        if err:
            lines.append(f"[{i}] id={aid} FAILED err={_trunc(str(err), 100)}")
        else:
            lines.append(f"[{i}] id={aid} sev={sev} anomalies={n_an} summary={summ}")
    lines.append(
        "TASK: Week-scale posture — sustained issues, noisy subsystems, model blind spots, or calibration hints. "
        "Stay grounded in the evidence lines above."
    )
    return "\n".join(lines)

"""Roll up daily analysis rows into ISO weeks and baseline copy for trend pages."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any


def _parse_day(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()


def weeks_from_daily(daily: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sum daily buckets into ISO year-week keys (week starts Monday)."""
    acc: dict[tuple[int, int], dict[str, Any]] = {}
    for r in daily:
        d = _parse_day(r["day"])
        y, w, _ = d.isocalendar()
        key = (y, w)
        if key not in acc:
            acc[key] = {
                "iso_year": y,
                "iso_week": w,
                "week_label": f"{y}-W{w:02d}",
                "week_start": date.fromisocalendar(y, w, 1).isoformat(),
                "analyses_total": 0,
                "ok_total": 0,
                "err_total": 0,
                "sev_info": 0,
                "sev_low": 0,
                "sev_medium": 0,
                "sev_high": 0,
                "sev_critical": 0,
                "anomalies_total": 0,
                "elevated_total": 0,
            }
        b = acc[key]
        b["analyses_total"] += int(r["analyses_total"])
        b["ok_total"] += int(r["ok_total"])
        b["err_total"] += int(r["err_total"])
        b["sev_info"] += int(r["sev_info"])
        b["sev_low"] += int(r["sev_low"])
        b["sev_medium"] += int(r["sev_medium"])
        b["sev_high"] += int(r["sev_high"])
        b["sev_critical"] += int(r["sev_critical"])
        b["anomalies_total"] += int(r["anomalies_total"])
        b["elevated_total"] += int(r["elevated_total"])

    out = sorted(acc.values(), key=lambda x: (x["iso_year"], x["iso_week"]))
    return out


def baseline_status(distinct_days_with_analysis: int, oldest_day: str | None, newest_day: str | None) -> dict[str, Any]:
    """How much history we have for honest trend reading."""
    if distinct_days_with_analysis <= 0 or not oldest_day or not newest_day:
        return {
            "level": "empty",
            "title": "No trend history yet",
            "body": "Once Ollama finishes a few analysis batches across different days, charts will appear here. Baselines need time: expect rough edges for the first week.",
        }
    if distinct_days_with_analysis < 3:
        return {
            "level": "seed",
            "title": "Seeding phase",
            "body": "Only a couple of calendar days include analyses. Trends are illustrative, not statistical. Check back after a few more daily wakes.",
        }
    if distinct_days_with_analysis < 7:
        return {
            "level": "young",
            "title": "Young dataset",
            "body": "Under a week of day buckets. Directional hints are fine; do not treat deltas as stable baselines yet.",
        }
    if distinct_days_with_analysis < 14:
        return {
            "level": "warming",
            "title": "Warming up",
            "body": "One to two weeks of history. Week-over-week comparisons start to mean something; seasonality and firewall noise still dominate.",
        }
    return {
        "level": "steady",
        "title": "Trends usable",
        "body": f"About {distinct_days_with_analysis} distinct days with analyses ({oldest_day} → {newest_day}). Elevated severities and anomaly counts are worth watching week to week.",
    }


def delta_narrative(rows: list[dict[str, Any]], label: str) -> str | None:
    """One sentence comparing last bucket to previous, if both exist."""
    nonempty = [r for r in rows if int(r.get("analyses_total", 0)) > 0]
    if len(nonempty) < 2:
        return None
    a, b = nonempty[-2], nonempty[-1]
    ok_d = int(b["ok_total"]) - int(a["ok_total"])
    el_d = int(b["elevated_total"]) - int(a["elevated_total"])
    an_d = int(b["anomalies_total"]) - int(a["anomalies_total"])
    parts = []
    if ok_d:
        parts.append(f"completed analyses {ok_d:+d}")
    if el_d:
        parts.append(f"high/critical bucket {el_d:+d}")
    if an_d:
        parts.append(f"reported anomalies {an_d:+d}")
    if not parts:
        return f"Last {label} looks similar to the prior one (same ballpark of analyses and flags)."
    return f"Versus the prior {label}: " + ", ".join(parts) + "."


def fill_daily_gaps(rows: list[dict[str, Any]], lookback_days: int) -> list[dict[str, Any]]:
    """Ensure every calendar day in range exists (zeros) so charts do not look broken."""
    if not rows and lookback_days <= 0:
        return []
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=lookback_days - 1)
    by_day = {r["day"]: r for r in rows}
    empty: dict[str, Any] = {
        "analyses_total": 0,
        "ok_total": 0,
        "err_total": 0,
        "sev_info": 0,
        "sev_low": 0,
        "sev_medium": 0,
        "sev_high": 0,
        "sev_critical": 0,
        "anomalies_total": 0,
        "elevated_total": 0,
    }
    out: list[dict[str, Any]] = []
    d = start
    while d <= today:
        key = d.isoformat()
        if key in by_day:
            out.append(dict(by_day[key]))
        else:
            out.append({"day": key, **empty})
        d += timedelta(days=1)
    return out


def max_bar_scalar(rows: list[dict[str, Any]]) -> int:
    m = 1
    for r in rows:
        m = max(
            m,
            int(r.get("analyses_total", 0)),
            int(r.get("ok_total", 0)) + int(r.get("err_total", 0)),
            int(r.get("elevated_total", 0)),
            max(1, int(r.get("anomalies_total", 0)) // 3),
        )
    return m

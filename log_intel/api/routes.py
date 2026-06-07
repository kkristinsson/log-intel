"""FastAPI routes for unified log-intel API."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from log_intel import __version__
from log_intel.adapters.loggy_reader import LoggyReader
from log_intel.adapters.netsyslog_reader import NetsyslogReader
from log_intel.adapters.syslogb_client import SyslogbClient
from log_intel.analysis import ollama_client
from log_intel.config import get_settings
from log_intel.hub_state import HubState
from log_intel.metrics import metrics_bytes
from log_intel.store import importance_for_event, to_stream_event

router = APIRouter()
_hub: HubState | None = None


def set_hub(state: HubState) -> None:
    global _hub
    _hub = state


def get_hub() -> HubState:
    if _hub is None:
        raise HTTPException(status_code=503, detail="Hub not initialized")
    return _hub


class AnalyzeRequest(BaseModel):
    event_ids: list[int] = Field(default_factory=list)
    scope: str = "batch"


class AlertRuleBody(BaseModel):
    id: str | None = None
    name: str
    enabled: bool = True
    query: str
    mode: str = "text"
    source_type: str | None = None
    scope: str = "all"
    cooldown_sec: int = 300
    webhook_url: str | None = None
    email_to: str | None = None


@router.get("/health")
def health() -> dict[str, Any]:
    hub = get_hub()
    ollama_ok, ollama_msg = ollama_client.health_check()
    return {
        "status": "ok",
        "version": __version__,
        "ollama": {"ok": ollama_ok, "message": ollama_msg},
        "adapters": hub.health_snapshot(),
    }


@router.get("/metrics")
def metrics() -> Response:
    return Response(content=metrics_bytes(), media_type="text/plain; version=0.0.4")


@router.get("/api/v1/events")
def list_events(
    hours: float = Query(24, ge=0.1, le=720),
    source_type: str | None = None,
    log_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    hub = get_hub()
    since = time.time() - hours * 3600
    events = hub.store.list_events(
        since=since,
        source_type=source_type,
        log_type=log_type,
        limit=limit,
        offset=offset,
    )
    return {"events": [e.to_dict() for e in events], "count": len(events)}


@router.get("/api/v1/search")
def search(
    q: str = Query(..., min_length=1),
    mode: str = Query("text"),
    source_type: str | None = None,
    hours: float = Query(168, ge=0.1, le=720),
    include_syslogb: bool = False,
    include_loggy: bool = False,
    limit: int = Query(200, ge=1, le=500),
) -> dict[str, Any]:
    hub = get_hub()
    since = time.time() - hours * 3600
    events = hub.store.search(q, mode=mode, source_type=source_type, since=since, limit=limit)
    results = [{"origin": "hub", **e.to_dict()} for e in events]

    if include_syslogb:
        for ev in hub.syslogb.search(q, mode=mode, limit=limit):
            results.append(
                {
                    "origin": "syslogb",
                    "source": ev.get("source"),
                    "line": ev.get("line"),
                    "ts": ev.get("ts"),
                    "received_at": ev.get("received_at"),
                }
            )

    if include_loggy:
        imported = hub.loggy.fetch_raw_logs(limit=limit)
        ql = q.lower()
        for ev in imported:
            if ql in (ev.message or "").lower():
                results.append({"origin": "loggy", **ev.to_dict()})

    return {"results": results[:limit], "count": min(len(results), limit)}


@router.get("/api/v1/flows")
def flows(
    hours: float = Query(24, ge=0.1, le=2160),
    limit: int = Query(2000, ge=1, le=50000),
    include_archive: bool = True,
) -> dict[str, Any]:
    hub = get_hub()
    since = time.time() - hours * 3600
    until = time.time()
    edges = hub.store.flow_aggregates(since, until, limit=limit)
    if include_archive and len(edges) < limit:
        archive = hub.netsyslog.fetch_flow_aggregates(hours=hours, limit=limit)
        seen = {(e["src_ip"], e["dst_ip"]) for e in edges}
        for e in archive:
            key = (e.get("src_ip"), e.get("dst_ip"))
            if key not in seen:
                edges.append(e)
                seen.add(key)
    return {"since": since, "until": until, "hours": hours, "edges": edges[:limit]}


@router.get("/api/v1/stream")
async def stream(
    importance_min: str = Query("info"),
    source_type: str | None = None,
) -> StreamingResponse:
    hub = get_hub()
    levels = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    min_level = levels.get(importance_min.lower(), 0)

    async def gen():
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        hub.stream_subscribers.append(q)
        try:
            for ev in list(hub.recent_stream):
                if levels.get(ev.importance, 0) >= min_level:
                    if source_type is None or ev.source_type == source_type:
                        yield f"data: {json.dumps(ev.__dict__)}\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if ev is None:
                    break
                if levels.get(ev.importance, 0) >= min_level:
                    if source_type is None or ev.source_type == source_type:
                        yield f"data: {json.dumps(ev.__dict__)}\n\n"
        finally:
            if q in hub.stream_subscribers:
                hub.stream_subscribers.remove(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/analyze")
def analyze(body: AnalyzeRequest) -> dict[str, Any]:
    hub = get_hub()
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids required")
    job_id = hub.analysis_worker.run_on_demand(body.event_ids)
    return {"job_id": job_id}


@router.get("/api/v1/analyze/{job_id}")
def analyze_status(job_id: str) -> dict[str, Any]:
    hub = get_hub()
    job = hub.store.get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/api/v1/alert-rules")
def list_alert_rules() -> dict[str, Any]:
    return {"rules": get_hub().store.list_alert_rules()}


@router.put("/api/v1/alert-rules")
def upsert_alert_rule(body: AlertRuleBody) -> dict[str, Any]:
    get_hub().store.upsert_alert_rule(body.model_dump())
    get_hub().alert_engine.reload_rules()
    return {"ok": True}


@router.delete("/api/v1/alert-rules/{rule_id}")
def delete_alert_rule(rule_id: str) -> dict[str, Any]:
    ok = get_hub().store.delete_alert_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"ok": True}


@router.get("/api/v1/alert-events")
def list_alert_events(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    return {"events": get_hub().store.list_alert_events(limit=limit)}


@router.post("/api/v1/webhooks/syslogb")
async def syslogb_webhook(request: Request) -> dict[str, Any]:
    body = await request.json()
    get_hub().alert_engine.ingest_syslogb_webhook(body)
    return {"ok": True}


@router.get("/api/v1/adapters/status")
def adapters_status() -> dict[str, Any]:
    hub = get_hub()
    return {
        "syslogb": hub.syslogb.health(),
        "loggy": hub.loggy.health(),
        "netsyslog": hub.netsyslog.health(),
    }


@router.get("/api/v1/firewall")
def firewall_view(
    hours: float = Query(24, ge=0.1, le=168),
    action: str | None = None,
    log_type: str = Query("TRAFFIC"),
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    hub = get_hub()
    since = time.time() - hours * 3600
    events = hub.store.list_events(
        since=since,
        source_type="palo_alto",
        log_type=log_type,
        limit=limit * 3,
    )
    if action:
        events = [e for e in events if (e.action or "").lower() == action.lower()]
    return {"events": [e.to_dict() for e in events[:limit]], "count": len(events[:limit])}


def mount_ui(app) -> None:
    static_dir = Path(__file__).resolve().parent.parent / "web" / "static"
    index = static_dir / "index.html"

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return HTMLResponse(index.read_text(encoding="utf-8"))

    @app.get("/static/{path:path}")
    def static_files(path: str):
        fp = static_dir / path
        if not fp.is_file():
            raise HTTPException(status_code=404)
        media = "application/octet-stream"
        if path.endswith(".css"):
            media = "text/css"
        elif path.endswith(".js"):
            media = "application/javascript"
        return Response(content=fp.read_bytes(), media_type=media)

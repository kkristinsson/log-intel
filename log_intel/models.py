"""Event data model for unified log storage."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LogEvent:
    received_at: float
    source_type: str  # palo_alto | generic | windows | imported
    remote_ip: str
    transport: str
    raw: str
    message: str
    parser: str
    syslog_host: str = ""
    facility: int | None = None
    severity: int | None = None
    log_type: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None
    action: str | None = None
    event_ts: float | None = None
    src_lat: float | None = None
    src_lon: float | None = None
    src_country: str | None = None
    dst_lat: float | None = None
    dst_lon: float | None = None
    dst_country: str | None = None
    source_id: str = "hub"
    id: int | None = None
    llm_severity: str | None = None
    llm_summary: str | None = None
    analysis_id: int | None = None
    analyzed_at: float | None = None

    def to_insert_row(self) -> tuple[Any, ...]:
        return (
            self.received_at,
            self.source_id,
            self.source_type,
            self.remote_ip,
            self.transport,
            self.syslog_host,
            self.facility,
            self.severity,
            self.raw,
            self.message,
            self.parser,
            self.log_type,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.proto,
            self.action,
            self.event_ts,
            self.src_lat,
            self.src_lon,
            self.src_country,
            self.dst_lat,
            self.dst_lon,
            self.dst_country,
        )

    @classmethod
    def from_row(cls, row: tuple[Any, ...]) -> LogEvent:
        return cls(
            id=row[0],
            received_at=row[1],
            source_id=row[2],
            source_type=row[3],
            remote_ip=row[4],
            transport=row[5],
            syslog_host=row[6] or "",
            facility=row[7],
            severity=row[8],
            raw=row[9] or "",
            message=row[10] or "",
            parser=row[11] or "",
            log_type=row[12],
            src_ip=row[13],
            dst_ip=row[14],
            src_port=row[15],
            dst_port=row[16],
            proto=row[17],
            action=row[18],
            event_ts=row[19],
            src_lat=row[20],
            src_lon=row[21],
            src_country=row[22],
            dst_lat=row[23],
            dst_lon=row[24],
            dst_country=row[25],
            llm_severity=row[26],
            llm_summary=row[27],
            analysis_id=row[28],
            analyzed_at=row[29],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "received_at": self.received_at,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "remote_ip": self.remote_ip,
            "transport": self.transport,
            "syslog_host": self.syslog_host,
            "message": self.message,
            "parser": self.parser,
            "log_type": self.log_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "action": self.action,
            "event_ts": self.event_ts,
            "src_lat": self.src_lat,
            "src_lon": self.src_lon,
            "src_country": self.src_country,
            "dst_lat": self.dst_lat,
            "dst_lon": self.dst_lon,
            "dst_country": self.dst_country,
            "llm_severity": self.llm_severity,
            "llm_summary": self.llm_summary,
        }


@dataclass
class StreamEvent:
    """Lightweight event for SSE live feed."""

    id: int
    received_at: float
    source_type: str
    message: str
    remote_ip: str
    log_type: str | None = None
    action: str | None = None
    importance: str = "info"

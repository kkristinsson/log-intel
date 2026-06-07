"""Heuristics for Palo Alto PAN-OS syslog CSV payloads."""

from __future__ import annotations

from dataclasses import dataclass
import re

# Stored on analyses.model for rows that never called Ollama.
AUTO_SKIP_MODEL = "(auto-skip)"

_PROTOCOLS = frozenset(
    {
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "ipv6-tcp",
        "ipv6-udp",
        "sctp",
    }
)
_TRAFFIC_BLOCKED_ACTIONS = frozenset(
    {
        "deny",
        "drop",
        "reset-client",
        "reset-server",
        "reset-both",
        "deny-all",
        "block",
        "block-ip",
    }
)
_THREAT_BLOCKED_ACTIONS = frozenset(
    {
        "block",
        "drop",
        "sinkhole",
        "deny",
        "reset-client",
        "reset-server",
        "reset-both",
    }
)
_KV_BLOCKED_ACTION = re.compile(
    r"(?i)\baction\s+(block|drop|deny|sinkhole|reset-(?:client|server|both))\b"
)


def _pan_csv_fields(message: str) -> list[str] | None:
    """Return comma-split PAN CSV fields after the RFC5424 ``- - - -`` marker."""
    marker = " - - - - "
    idx = message.find(marker)
    if idx >= 0:
        payload = message[idx + len(marker) :].strip()
    else:
        m = re.search(r"(?<![0-9])(\d+,\d{4}/\d{2}/\d{2}\s)", message)
        if not m:
            return None
        payload = message[m.start(1) :].strip()
    if not payload:
        return None
    return payload.split(",")


def _action_after_protocol(fields: list[str]) -> str | None:
    for i, field in enumerate(fields):
        if field.strip().lower() in _PROTOCOLS and i + 1 < len(fields):
            return fields[i + 1].strip().lower()
    return None


def is_already_blocked(message: str) -> bool:
    """True when the firewall already denied/blocked the session (no LLM triage needed)."""
    fields = _pan_csv_fields(message)
    if not fields or len(fields) < 4:
        return False

    log_type = fields[3].strip().upper()
    if log_type == "TRAFFIC":
        action = _action_after_protocol(fields)
        return action in _TRAFFIC_BLOCKED_ACTIONS if action else False

    if log_type == "THREAT":
        action = _action_after_protocol(fields)
        if action in _THREAT_BLOCKED_ACTIONS:
            return True
        return _KV_BLOCKED_ACTION.search(message) is not None

    return False


@dataclass(frozen=True)
class TrafficFlow:
    src_ip: str
    dst_ip: str
    action: str


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _first_two_ipv4(fields: list[str]) -> tuple[str | None, str | None]:
    ips = []
    for f in fields:
        s = f.strip()
        if _IPV4_RE.match(s):
            ips.append(s)
            if len(ips) >= 2:
                break
    if len(ips) >= 2:
        return ips[0], ips[1]
    return None, None


def parse_allowed_traffic_flow(message: str) -> TrafficFlow | None:
    """Parse a PAN-OS TRAFFIC log and return a flow only if action is allow.

    This is intentionally heuristic: it aims to be good enough for dashboards without
    implementing the full PAN CSV schema.
    """
    fields = _pan_csv_fields(message)
    if not fields or len(fields) < 4:
        return None
    if fields[3].strip().upper() != "TRAFFIC":
        return None
    action = (_action_after_protocol(fields) or "").strip().lower()
    if action != "allow":
        return None
    src_ip, dst_ip = _first_two_ipv4(fields)
    if not src_ip or not dst_ip:
        return None
    return TrafficFlow(src_ip=src_ip, dst_ip=dst_ip, action=action)

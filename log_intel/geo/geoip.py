"""GeoIP lookup via local MMDB (adapted from netsyslog)."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

import maxminddb

log = logging.getLogger(__name__)


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _country_iso(rec: dict[str, Any]) -> str | None:
    country = rec.get("country")
    if isinstance(country, dict):
        code = country.get("iso_code")
        if isinstance(code, str) and code:
            return code
    return None


def _lat_lon(rec: dict[str, Any]) -> tuple[float, float] | None:
    loc = rec.get("location")
    if not isinstance(loc, dict):
        return None
    lat, lon = loc.get("latitude"), loc.get("longitude")
    if lat is None or lon is None:
        return None
    try:
        return float(lat), float(lon)
    except (TypeError, ValueError):
        return None


class GeoLookup:
    def __init__(self, mmdb_path: str | None) -> None:
        self._reader: maxminddb.Reader | None = None
        if mmdb_path and Path(mmdb_path).is_file():
            self._reader = maxminddb.open_database(mmdb_path)
            log.info("MMDB geolocation loaded from %s", mmdb_path)
        else:
            log.warning("MMDB not found at %s — geolocation disabled", mmdb_path)

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def lookup(self, ip: str) -> dict[str, Any] | None:
        if self._reader is None or not _is_public(ip):
            return None
        try:
            rec = self._reader.get(ip)
        except Exception:
            return None
        if not isinstance(rec, dict):
            return None
        coords = _lat_lon(rec)
        if coords is None:
            return None
        lat, lon = coords
        return {"lat": lat, "lon": lon, "country": _country_iso(rec)}


def enrich_event(ev: object, geo: GeoLookup) -> None:
    for ip, prefix in ((getattr(ev, "src_ip", None), "src"), (getattr(ev, "dst_ip", None), "dst")):
        if not ip:
            continue
        g = geo.lookup(ip)
        if g:
            setattr(ev, f"{prefix}_lat", g["lat"])
            setattr(ev, f"{prefix}_lon", g["lon"])
            setattr(ev, f"{prefix}_country", g["country"])

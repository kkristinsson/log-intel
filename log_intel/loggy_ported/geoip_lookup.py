"""Optional GeoIP lookups (used for the flows map)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from log_intel import hub_config as config


@dataclass(frozen=True)
class GeoPoint:
    lat: float
    lon: float
    country: str
    city: str
    asn: str


def _reader_or_none(path: str):
    if not path:
        return None
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    # Import only if configured so base installs still run.
    from geoip2.database import Reader  # type: ignore

    return Reader(str(p))


@lru_cache(maxsize=1)
def _city_reader():
    return _reader_or_none(config.GEOIP_CITY_DB)


@lru_cache(maxsize=1)
def _asn_reader():
    return _reader_or_none(config.GEOIP_ASN_DB)


def enabled() -> bool:
    return _city_reader() is not None


def lookup(ip: str) -> GeoPoint | None:
    """Return GeoPoint for an IP, or None if DBs not configured / IP unknown."""
    city = _city_reader()
    if city is None:
        return None
    try:
        r = city.city(ip)
    except Exception:
        return None
    if not r.location or r.location.latitude is None or r.location.longitude is None:
        return None
    country = (r.country.iso_code or r.country.name or "").strip()
    city_name = (r.city.name or "").strip()
    lat = float(r.location.latitude)
    lon = float(r.location.longitude)

    asn_val = ""
    asn = _asn_reader()
    if asn is not None:
        try:
            a = asn.asn(ip)
            org = (a.autonomous_system_organization or "").strip()
            num = a.autonomous_system_number
            if num and org:
                asn_val = f"AS{num} {org}"
            elif num:
                asn_val = f"AS{num}"
            elif org:
                asn_val = org
        except Exception:
            asn_val = ""
    return GeoPoint(lat=lat, lon=lon, country=country, city=city_name, asn=asn_val)


#!/usr/bin/env bash
# Backup log-intel SQLite databases and optional GeoIP file.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${LOG_INTEL_DATA_DIR:-$ROOT/data}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${1:-$ROOT/backups/log-intel-$STAMP}"

mkdir -p "$DEST"
cp -a "$DATA/analyses.db" "$DEST/" 2>/dev/null || true
cp -a "$DATA/events.sqlite" "$DEST/" 2>/dev/null || true
cp -a "$ROOT/geoip/dbip-city-lite.mmdb" "$DEST/" 2>/dev/null || true

echo "Backup written to $DEST"

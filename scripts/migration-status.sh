#!/usr/bin/env bash
# Quick migration checklist for log-intel on this host.
set -euo pipefail

HOST_IP="${HOST_IP:-$(hostname -I | awk '{print $1}')}"
HUB_HTTP="${LOG_INTEL_HOST_HTTP_PORT:-9088}"
HUB_SYSLOG="${LOG_INTEL_HOST_SYSLOG_PORT:-5516}"

echo "=== log-intel migration status ==="
echo "Host IP: $HOST_IP"
echo ""

echo "--- Hub ---"
curl -sf "http://127.0.0.1:${HUB_HTTP}/health" | python3 -m json.tool 2>/dev/null || echo "Hub not reachable on :${HUB_HTTP}"
echo ""

echo "--- Adapter mounts ---"
docker exec log-intel ls -la /loggy/loggy.db /netsyslog/events.sqlite 2>/dev/null || echo "Container not running or DB paths missing"
echo ""

echo "--- Manual steps (cannot automate from this host) ---"
echo "Phase 1 PA fan-out: add syslog server ${HOST_IP}:${HUB_SYSLOG} (UDP/TCP) alongside existing loggy ${HOST_IP}:5514"
echo "Phase 2 syslogb:   alert webhook → http://${HOST_IP}:${HUB_HTTP}/api/v1/webhooks/syslogb"
echo "Phase 3 cutover:   PA → ${HOST_IP}:${HUB_SYSLOG} only, then stop loggy syslog publish"
echo "Windows:           syslog-pusher/dist/SyslogPusher.exe → ${HOST_IP}:${HUB_SYSLOG} (or rsyslog :514 for file bridge)"
echo ""

echo "--- Optional rsyslog file bridge (syslogb) ---"
echo "  sudo cp config/rsyslog/50-log-intel-incoming.conf /etc/rsyslog.d/"
echo "  sudo rsyslogd -N1 && sudo systemctl restart rsyslog"

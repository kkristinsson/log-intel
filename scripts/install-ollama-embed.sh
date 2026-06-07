#!/usr/bin/env bash
# Dedicated Ollama instance for log-intel RAG embeddings (port 11435, nomic-embed-text).
# Normally invoked by ./install.sh — run manually only if that step failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "install-ollama-embed.sh: $*" >&2; exit 1; }
warn() { echo "install-ollama-embed.sh: warning: $*" >&2; }

PORT="${LOG_INTEL_OLLAMA_PORT:-${SYSLOGB_OLLAMA_PORT:-11435}}"
EMBED_MODEL="${OLLAMA_EMBED_MODEL:-nomic-embed-text}"
MODELS_DIR="${LOG_INTEL_OLLAMA_MODELS_DIR:-${SYSLOGB_OLLAMA_MODELS_DIR:-$ROOT/data/ollama}}"
OLLAMA_HOST="127.0.0.1:${PORT}"
BASE_URL="http://${OLLAMA_HOST}"
SERVICE_NAME="ollama-log-intel"

if [[ "${LOG_INTEL_SKIP_OLLAMA:-${SYSLOGB_SKIP_OLLAMA:-0}}" == "1" ]]; then
  echo "LOG_INTEL_SKIP_OLLAMA=1 — skipping Ollama embed install."
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  warn "Ollama auto-install is supported on Linux only."
  echo "Run Ollama manually with OLLAMA_HOST=${OLLAMA_HOST} and pull ${EMBED_MODEL}"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  die "curl is required to install Ollama"
fi

install_ollama_binary() {
  mkdir -p "$ROOT/data"
  if command -v ollama >/dev/null 2>&1; then
    echo "Ollama binary already installed: $(command -v ollama)"
    return 0
  fi
  echo "Installing Ollama via https://ollama.com/install.sh ..."
  curl -fsSL https://ollama.com/install.sh | sh
  command -v ollama >/dev/null 2>&1 || die "Ollama install finished but ollama not in PATH"
}

OLLAMA_BIN="$(command -v ollama 2>/dev/null || true)"
install_ollama_binary
OLLAMA_BIN="$(command -v ollama)"

mkdir -p "$MODELS_DIR"

INSTALL_USER="${SUDO_USER:-${USER:-root}}"
if [[ "$INSTALL_USER" == "root" ]]; then
  SERVICE_USER="root"
  SERVICE_GROUP="root"
  SERVICE_HOME="/var/lib/ollama-log-intel"
else
  SERVICE_USER="$INSTALL_USER"
  SERVICE_GROUP="$(id -gn "$INSTALL_USER" 2>/dev/null || echo "$INSTALL_USER")"
  SERVICE_HOME="$(getent passwd "$INSTALL_USER" | cut -d: -f6 || echo "/home/$INSTALL_USER")"
fi
mkdir -p "$SERVICE_HOME"
if [[ "$INSTALL_USER" != "root" ]]; then
  chown "$SERVICE_USER:$SERVICE_GROUP" "$SERVICE_HOME" 2>/dev/null || true
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$MODELS_DIR" 2>/dev/null || true
fi

install_systemd_unit() {
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found — start Ollama manually."
    return 1
  fi
  local unit_src="$ROOT/config/systemd/ollama-syslogb.service"
  [[ -f "$unit_src" ]] || die "missing $unit_src"

  local unit_dest="/etc/systemd/system/${SERVICE_NAME}.service"
  local tmp
  tmp="$(mktemp)"
  sed \
    -e "s|OLLAMA_BIN_PLACEHOLDER|${OLLAMA_BIN}|g" \
    -e "s|OLLAMA_PORT_PLACEHOLDER|${PORT}|g" \
    -e "s|OLLAMA_MODELS_PLACEHOLDER|${MODELS_DIR}|g" \
    -e "s|SERVICE_USER_PLACEHOLDER|${SERVICE_USER}|g" \
    -e "s|SERVICE_GROUP_PLACEHOLDER|${SERVICE_GROUP}|g" \
    -e "s|SERVICE_HOME_PLACEHOLDER|${SERVICE_HOME}|g" \
    -e "s|ROOT_PLACEHOLDER|${ROOT}|g" \
    -e "s|ollama-syslogb|ollama-log-intel|g" \
    "$unit_src" > "$tmp"

  if [[ -w /etc/systemd/system ]]; then
    cp "$tmp" "$unit_dest"
  elif command -v sudo >/dev/null 2>&1; then
    sudo cp "$tmp" "$unit_dest"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$SERVICE_NAME"
    rm -f "$tmp"
    return 0
  else
    rm -f "$tmp"
    warn "Cannot write ${unit_dest}"
    return 1
  fi
  rm -f "$tmp"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

if install_systemd_unit; then
  echo "Started systemd unit ${SERVICE_NAME} (OLLAMA_HOST=${OLLAMA_HOST})"
else
  warn "Starting Ollama in background without systemd ..."
  OLLAMA_HOST="$OLLAMA_HOST" OLLAMA_MODELS="$MODELS_DIR" nohup "$OLLAMA_BIN" serve \
    >>"$ROOT/data/ollama-embed.log" 2>&1 &
  disown 2>/dev/null || true
fi

echo "Waiting for Ollama at ${BASE_URL} ..."
ready=0
for _ in $(seq 1 60); do
  if curl -sf "${BASE_URL}/api/tags" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == "1" ]] || die "Ollama did not become ready at ${BASE_URL}"

echo "Pulling embed model ${EMBED_MODEL} ..."
OLLAMA_HOST="$OLLAMA_HOST" OLLAMA_MODELS="$MODELS_DIR" "$OLLAMA_BIN" pull "$EMBED_MODEL"

echo
echo "Ollama embed server ready at ${BASE_URL} (model ${EMBED_MODEL})"

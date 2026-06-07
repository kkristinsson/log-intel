#!/usr/bin/env bash
# Install log-intel (syslogb file UI + network hub) — venv, deps, .env, optional embed server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

die() { echo "install.sh: $*" >&2; exit 1; }

[[ -f "$ROOT/pyproject.toml" && -f "$ROOT/log_intel/main.py" ]] || \
  die "run from the log-intel directory"

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || die "python3 not found (need 3.11+)"

PY_VER="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER#*.}"
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 11) )); then
  die "Python 3.11+ required (found $PY_VER)"
fi

VENV="$ROOT/.venv"
if [[ ! -d "$VENV" ]]; then
  echo "Creating virtual environment in .venv ..."
  "$PYTHON" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install -U pip wheel
python -m pip install -e .

CREATED_ENV=0
if [[ ! -f "$ROOT/.env" ]]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  CREATED_ENV=1
  echo "Created .env from .env.example"
fi

python <<'PY'
import pathlib
import re
import secrets

env = pathlib.Path(".env")
text = env.read_text()
if re.search(r"^FLASK_SECRET_KEY=(change-me.*)?\s*$", text, re.M) or re.search(
    r"^FLASK_SECRET_KEY=\s*$", text, re.M
):
    text = re.sub(
        r"^FLASK_SECRET_KEY=.*$",
        f"FLASK_SECRET_KEY={secrets.token_hex(32)}",
        text,
        count=1,
        flags=re.M,
    )
    env.write_text(text)
    print("Generated FLASK_SECRET_KEY in .env")
PY

mkdir -p "$ROOT/data" "$ROOT/geoip"

# Default log dirs: include /var/log/remote when present (rsyslog remote hosts)
if [[ -d /var/log/remote ]] && ! grep -q '^LOG_DIRS=' "$ROOT/.env" 2>/dev/null; then
  echo "LOG_DIRS=/var/log,/var/log/remote" >> "$ROOT/.env"
  echo "LOG_RECURSIVE=1" >> "$ROOT/.env"
fi

# LLM setup (same menu as syslogb; accepts LOG_INTEL_LLM_SETUP or SYSLOGB_LLM_SETUP)
LLM_SETUP="${LOG_INTEL_LLM_SETUP:-${SYSLOGB_LLM_SETUP:-}}"
[[ -z "$LLM_SETUP" && "${SYSLOGB_BERGET_AI:-}" == "1" ]] && LLM_SETUP=berget
[[ -z "$LLM_SETUP" && "${SYSLOGB_GROK_AI:-}" == "1" ]] && LLM_SETUP=grok

if [[ -z "$LLM_SETUP" && -t 0 ]]; then
  echo
  echo "Which LLM setup do you want?"
  echo "  1) Berget AI           — remote chat + embeddings (api.berget.ai)"
  echo "  2) Grok / xAI          — remote chat; local Ollama for embeddings"
  echo "  3) OpenAI / compatible — remote chat; local Ollama for embeddings [default]"
  echo "  4) All-local Ollama    — chat and embeddings on this machine"
  read -r -p "Choice [1-4, default 3]: " _llm_choice
  case "${_llm_choice:-3}" in
    1) LLM_SETUP=berget ;;
    2) LLM_SETUP=grok ;;
    4) LLM_SETUP=ollama ;;
    *) LLM_SETUP=openai ;;
  esac
fi

[[ -z "$LLM_SETUP" && "$CREATED_ENV" == "1" ]] && LLM_SETUP=openai

OLLAMA_BASE_URL="${LOG_INTEL_OLLAMA_BASE_URL:-${SYSLOGB_OLLAMA_BASE_URL:-${SYSLOGB_OLLAMA_HOST:-}}}"
if [[ "$LLM_SETUP" == "ollama" && -z "$OLLAMA_BASE_URL" && -t 0 ]]; then
  read -r -p "Ollama host or URL [127.0.0.1:11434]: " _ollama_host
  OLLAMA_BASE_URL="${_ollama_host:-127.0.0.1:11434}"
fi

REMOTE_API_KEY="${LOG_INTEL_LLM_API_KEY:-${SYSLOGB_LLM_API_KEY:-${SYSLOGB_BERGET_API_KEY:-}}}"
if [[ "$LLM_SETUP" == "berget" || "$LLM_SETUP" == "grok" || "$LLM_SETUP" == "openai" ]]; then
  if [[ -z "$REMOTE_API_KEY" && -t 0 ]]; then
    case "$LLM_SETUP" in
      berget) _key_label="Berget AI" ;;
      grok) _key_label="Grok / xAI" ;;
      *) _key_label="API" ;;
    esac
    echo -n "${_key_label} API key: "
    read -rs REMOTE_API_KEY
    echo
  fi
fi

INSTALL_OLLAMA_EMBED=0
case "$LLM_SETUP" in
  berget) echo "Berget AI: chat + embeddings via api.berget.ai" ;;
  ollama)
    echo "All-local Ollama on ${OLLAMA_BASE_URL:-127.0.0.1:11434}"
    ;;
  grok)
    echo "Grok/xAI chat + local embed server on :11435"
    INSTALL_OLLAMA_EMBED=1
    ;;
  openai|"")
    [[ -n "$LLM_SETUP" ]] && echo "OpenAI-compatible chat + local embed on :11435"
    INSTALL_OLLAMA_EMBED=1
    ;;
esac

if [[ "$INSTALL_OLLAMA_EMBED" == "1" ]]; then
  echo "Setting up local embedding server for large-file RAG ..."
  if [[ "${LOG_INTEL_SKIP_OLLAMA:-${SYSLOGB_SKIP_OLLAMA:-0}}" == "1" ]]; then
    echo "LOG_INTEL_SKIP_OLLAMA=1 — skipping embed server"
  elif [[ -x "$ROOT/scripts/install-ollama-embed.sh" ]]; then
    "$ROOT/scripts/install-ollama-embed.sh" || \
      echo "install.sh: warning: embed server setup failed — retry ./scripts/install-ollama-embed.sh" >&2
  fi
fi

_seed_env() {
  LOG_INTEL_LLM_SETUP="${LLM_SETUP:-openai}" \
  LOG_INTEL_LLM_API_KEY="${REMOTE_API_KEY:-}" \
  LOG_INTEL_OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-}" \
  python <<'PY'
import os
import pathlib
import re

setup = os.environ.get("LOG_INTEL_LLM_SETUP", "openai").strip().lower()
api_key = os.environ.get("LOG_INTEL_LLM_API_KEY", "").strip()
env = pathlib.Path(".env")
text = env.read_text()


def normalize_ollama_base(raw: str, *, default_port: str = "11434") -> str:
    s = (raw or "").strip()
    if not s:
        return f"http://127.0.0.1:{default_port}"
    if s.startswith("http://") or s.startswith("https://"):
        return s.rstrip("/")
    if ":" not in s:
        s = f"{s}:{default_port}"
    return f"http://{s}".rstrip("/")


def set_or_append(key: str, value: str) -> None:
    global text
    pat = re.compile(rf"^{re.escape(key)}=.*$", re.M)
    line = f"{key}={value}"
    if pat.search(text):
        text = pat.sub(line, text, count=1)
    else:
        text = text.rstrip() + "\n" + line + "\n"


def set_chat_model_if_empty(model: str) -> None:
    if not re.search(r"^LLM_CHAT_MODEL=.*\S", text, re.M):
        set_or_append("LLM_CHAT_MODEL", model)

# log-intel paths (always)
set_or_append("LOG_INTEL_DATA_DIR", "./data")
set_or_append("DATA_DIR", "./data")
set_or_append("LOG_INTEL_SQLITE_PATH", "./data/events.sqlite")
set_or_append("LOG_INTEL_GEOIP_MMDB_PATH", "./geoip/dbip-city-lite.mmdb")
set_or_append("LOG_INTEL_HTTP_PORT", "9088")
set_or_append("LLM_ENABLED", "1")

if setup == "berget":
    set_or_append("LLM_PROVIDER", "openai")
    set_or_append("LLM_API_BASE_URL", "https://api.berget.ai/v1")
    set_or_append("LLM_EMBED_MODEL", "multilingual-e5-large")
    set_or_append("EMBED_MAX_CHARS", "1800")
    set_or_append("EMBED_MAX_TOKENS_PER_INPUT", "512")
    set_or_append("EMBED_MAX_TOKENS_PER_REQUEST", "480")
    set_or_append("EMBED_BATCH_SIZE", "4")
    set_chat_model_if_empty("gpt-oss-120b")
    set_or_append("LOG_INTEL_LLM_ENABLED", "0")
    if api_key:
        set_or_append("LLM_API_KEY", api_key)
elif setup == "grok":
    set_or_append("LLM_PROVIDER", "hybrid")
    set_or_append("LLM_API_BASE_URL", "https://api.x.ai/v1")
    set_or_append("OLLAMA_BASE_URL", "http://127.0.0.1:11435")
    set_or_append("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    set_chat_model_if_empty("grok-4.3")
    set_or_append("LOG_INTEL_LLM_ENABLED", "0")
    if api_key:
        set_or_append("LLM_API_KEY", api_key)
elif setup == "ollama":
    ollama_base = normalize_ollama_base(os.environ.get("LOG_INTEL_OLLAMA_BASE_URL", ""))
    set_or_append("LLM_PROVIDER", "ollama")
    set_or_append("OLLAMA_BASE_URL", ollama_base)
    set_or_append("OLLAMA_MODEL", "qwen3.6:27b-q8_0")
    set_or_append("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    set_or_append("LOG_INTEL_LLM_ENABLED", "1")
else:
    set_or_append("LLM_PROVIDER", "hybrid")
    set_or_append("OLLAMA_BASE_URL", "http://127.0.0.1:11435")
    set_or_append("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    set_or_append("LOG_INTEL_LLM_ENABLED", "0")
    if not re.search(r"^LLM_API_BASE_URL=.*$", text, re.M):
        set_or_append("LLM_API_BASE_URL", "https://api.openai.com/v1")
    if api_key:
        set_or_append("LLM_API_KEY", api_key)

env.write_text(text)
print(f"Configured .env for LLM setup: {setup}")
PY
  unset LOG_INTEL_LLM_API_KEY
}

REMOTE_KEY_SAVED=0
[[ -n "$REMOTE_API_KEY" ]] && REMOTE_KEY_SAVED=1

if [[ -n "$LLM_SETUP" ]] || [[ "$CREATED_ENV" == "1" ]]; then
  _seed_env
fi
unset REMOTE_API_KEY

chmod +x "$ROOT/scripts/install-ollama-embed.sh" 2>/dev/null || true

echo
echo "log-intel installed in: $ROOT"
echo
echo "Next steps:"
echo "  1. Copy GeoIP database to geoip/dbip-city-lite.mmdb (optional, for /hub geo map)"
echo "  2. Edit .env — LOG_DIRS, auth (AUTH_ENABLED), branding (BRAND_LOGO)"
if [[ "$REMOTE_KEY_SAVED" != "1" && "$LLM_SETUP" != "ollama" && "$LLM_SETUP" != "berget" ]]; then
  echo "     Add LLM_API_KEY if using remote chat"
fi
echo "  3. Native dev:  source .venv/bin/activate && log-intel"
echo "     Production:   gunicorn -w 1 -k gthread --threads 8 --timeout 600 -b 0.0.0.0:9088 log_intel.wsgi:application"
echo "     Docker:       docker compose up -d --build"
echo
echo "  File logs UI:  http://localhost:9088/"
echo "  Network hub:   http://localhost:9088/hub"
echo "  Syslog ingest: UDP/TCP port 514 (or LOG_INTEL_SYSLOG_UDP_PORT if busy)"
echo
echo "Non-interactive LLM: LOG_INTEL_LLM_SETUP=berget|grok|openai|ollama LOG_INTEL_LLM_API_KEY='…' ./install.sh"
echo "Skip embed server: LOG_INTEL_SKIP_OLLAMA=1 ./install.sh"
echo
echo "Optional: read /var/log — sudo usermod -aG adm \"\$USER\" && newgrp adm"
echo "See README.md and DEPRECATION.md for migration from syslogb/loggy/netsyslog."

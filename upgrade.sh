#!/usr/bin/env bash
# Upgrade an existing log-intel install from a GitHub tarball.
#
# Preserves local state: .env, data/, geoip/, .venv
# Then reinstalls Python deps and optionally restarts systemd.
#
# Usage:
#   ./upgrade.sh                  # latest GitHub release, else main
#   ./upgrade.sh 0.9.2            # tag v0.9.2 or 0.9.2
#   ./upgrade.sh v0.9.2
#   ./upgrade.sh test/bugfix-hardening
#   ./upgrade.sh main
#
# Env:
#   LOG_INTEL_GITHUB_REPO   owner/repo (default: kkristinsson/log-intel)
#   LOG_INTEL_SKIP_RESTART=1
#   LOG_INTEL_SKIP_PIP=1
#   LOG_INTEL_DRY_RUN=1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

die() { echo "upgrade.sh: $*" >&2; exit 1; }
info() { echo "upgrade.sh: $*"; }

[[ -f "$ROOT/pyproject.toml" && -f "$ROOT/log_intel/main.py" ]] || \
  die "run from the log-intel directory (pyproject.toml + log_intel/ missing)"

REPO="${LOG_INTEL_GITHUB_REPO:-kkristinsson/log-intel}"
REF_ARG="${1:-}"
DRY_RUN="${LOG_INTEL_DRY_RUN:-0}"
SKIP_PIP="${LOG_INTEL_SKIP_PIP:-0}"
SKIP_RESTART="${LOG_INTEL_SKIP_RESTART:-0}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required"
}

need_cmd curl
need_cmd tar
need_cmd python3

current_version() {
  if [[ -f "$ROOT/log_intel/syslogb/app/version.py" ]]; then
    python3 -c "import pathlib,re; t=pathlib.Path('log_intel/syslogb/app/version.py').read_text(); m=re.search(r'__version__\\s*=\\s*[\"\\']([^\"\\']+)[\"\\']', t); print(m.group(1) if m else 'unknown')"
  else
    echo "unknown"
  fi
}

resolve_ref() {
  local arg="$1"
  if [[ -z "$arg" ]]; then
    local tag
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("tag_name",""))' 2>/dev/null || true)"
    if [[ -n "$tag" && "$tag" != "null" ]]; then
      echo "$tag"
      return
    fi
    echo "main"
    return
  fi
  echo "$arg"
}

tarball_url_for_ref() {
  local ref="$1"
  # Prefer release/tag URL when it looks like a version; fall back to generic archive.
  local candidates=()
  if [[ "$ref" =~ ^v?[0-9]+\.[0-9]+ ]]; then
    local tag="$ref"
    [[ "$tag" == v* ]] || tag="v${tag}"
    candidates+=(
      "https://github.com/${REPO}/archive/refs/tags/${tag}.tar.gz"
      "https://github.com/${REPO}/archive/refs/tags/${ref}.tar.gz"
    )
  fi
  candidates+=(
    "https://github.com/${REPO}/archive/refs/heads/${ref}.tar.gz"
    "https://api.github.com/repos/${REPO}/tarball/${ref}"
  )
  local url
  for url in "${candidates[@]}"; do
    if curl -fsSIL -o /dev/null "$url" 2>/dev/null; then
      echo "$url"
      return
    fi
  done
  return 1
}

REF="$(resolve_ref "$REF_ARG")"
BEFORE="$(current_version)"
info "install root: $ROOT"
info "current version: $BEFORE"
info "target ref: ${REPO}@${REF}"

URL="$(tarball_url_for_ref "$REF")" || die "could not find a downloadable archive for ${REPO}@${REF}"
info "archive: $URL"

if [[ "$DRY_RUN" == "1" ]]; then
  info "dry run — no files changed"
  exit 0
fi

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/log-intel-upgrade.XXXXXX")"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

ARCHIVE="$STAGING/src.tar.gz"
EXTRACT="$STAGING/extract"
mkdir -p "$EXTRACT"

info "downloading ..."
curl -fsSL "$URL" -o "$ARCHIVE"

info "extracting ..."
tar -xzf "$ARCHIVE" -C "$EXTRACT"
SRC="$(find "$EXTRACT" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$SRC" && -f "$SRC/pyproject.toml" && -d "$SRC/log_intel" ]] || \
  die "archive did not contain a log-intel source tree"

# Local state that must never be replaced from the tarball.
PRESERVE=(
  ".env"
  "data"
  "geoip"
  ".venv"
  "backups"
)

info "syncing code (preserving ${PRESERVE[*]}) ..."
RSYNC_EXCLUDES=()
for p in "${PRESERVE[@]}"; do
  RSYNC_EXCLUDES+=(--exclude "$p")
done

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    "${RSYNC_EXCLUDES[@]}" \
    --exclude ".git" \
    "$SRC"/ "$ROOT"/
else
  info "rsync not found — using tar copy (no delete of removed upstream files)"
  (
    cd "$SRC"
    tar -cf - \
      --exclude='.env' \
      --exclude='data' \
      --exclude='geoip' \
      --exclude='.venv' \
      --exclude='backups' \
      --exclude='.git' \
      .
  ) | tar -xf - -C "$ROOT"
fi

# Ensure runtime dirs still exist after sync.
mkdir -p "$ROOT/data" "$ROOT/geoip"

if [[ "$SKIP_PIP" != "1" ]]; then
  VENV="$ROOT/.venv"
  if [[ ! -d "$VENV" ]]; then
    info "no .venv — creating one"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  info "reinstalling Python package into .venv ..."
  python -m pip install -U pip wheel >/dev/null
  python -m pip install -e .
else
  info "skipping pip reinstall (LOG_INTEL_SKIP_PIP=1)"
fi

AFTER="$(current_version)"
info "version after upgrade: $AFTER (was $BEFORE)"

restart_service() {
  local unit="${LOG_INTEL_SYSTEMD_UNIT:-log-intel}"
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi
  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    info "restarting systemd unit ${unit} ..."
    if systemctl restart "$unit" 2>/dev/null; then
      return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
      sudo systemctl restart "$unit"
      return 0
    fi
  fi
  return 1
}

if [[ "$SKIP_RESTART" == "1" ]]; then
  info "skipping service restart (LOG_INTEL_SKIP_RESTART=1)"
elif restart_service; then
  info "service restarted"
else
  info "restart the app manually, e.g.:"
  info "  sudo systemctl restart log-intel"
  info "  # or: source .venv/bin/activate && log-intel"
fi

echo
info "upgrade complete"
info "preserved: .env data/ geoip/ .venv/ backups/"
info "File logs:  http://localhost:9088/"
info "Network hub: http://localhost:9088/hub"

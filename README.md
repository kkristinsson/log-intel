<p align="center">
  <img src="log_intel/syslogb/web/static/branding/log-intel.png" alt="log-intel" width="280">
</p>

# log-intel — Unified Log Intelligence

Single app combining **file log tail/search/LLM** and a **network hub** (syslog ingest, Palo Alto parsing, geo flows, Juniper Mist), plus **Syslog Pusher** (Windows client) in the same repo.

Replaces standalone **syslogb**, **loggy**, **netsyslog**, and **syslogpusher**. See [DEPRECATION.md](DEPRECATION.md).

| Component | Where |
|-----------|--------|
| File logs | http://host:9088/ |
| Network hub | http://host:9088/hub |
| Syslog ingest (Linux hub) | UDP/TCP **514** (or remapped host port, e.g. **5516**) |
| Windows client | [`syslog-pusher/`](syslog-pusher/) — `dist/SyslogPusher-0.9.1.exe` |

## Features

**File logs (`/`)** — multi-directory tail, **systemd journal** (`journalctl`), search, export, LLM analysis, RAG/Chroma, alerts, auth, settings wizard.

**Network hub (`/hub`)** — Palo Alto + Windows syslog ingest, GeoIP, live feed (optional file/journal failures), **unified search** across hub + files + loggy archive, firewall view, flow map, **LLM analysis** (hourly/trends/on-demand), **unified alerts** (hub + file/journal tail).

**Unified intelligence (v0.9.1)** — cross-source search, multiplex live stream, EventStore schema v2 (`analyses` + `meta_summaries`), runtime `config/sources.yaml`, journal window LLM, single alert engine on `events.sqlite`. Migrate syslogb alert rules: `scripts/migrate-alert-rules.py`.

**Syslog Pusher (Windows)** — [`syslog-pusher/`](syslog-pusher/) forwards Windows event logs and watched log files to the hub (or rsyslog). Pre-built installer: `syslog-pusher/dist/SyslogPusher-0.9.1.exe`.

## Requirements

- Python **3.11+** (native install) or Docker
- Read access to log directories (often `adm` group on Linux)
- **GeoIP** (optional): DB-IP Lite or GeoLite2 City → `geoip/dbip-city-lite.mmdb`
- **LLM** (optional): OpenAI-compatible API, Berget, Grok, or local Ollama — same choices as syslogb

Tail, search, and hub ingest work without any LLM.

## Quick start (recommended)

Same one-step flow as syslogb:

```bash
git clone <your-repo>/log-intel.git
cd log-intel
./install.sh
```

`install.sh` creates a venv, installs dependencies, seeds `.env`, generates `FLASK_SECRET_KEY`, and (for hybrid/OpenAI/Grok setups) runs the local **embed server** on port **11435** automatically.

Then start:

```bash
source .venv/bin/activate
log-intel                    # dev server
# or production:
gunicorn -w 1 -k gthread --threads 8 --timeout 600 \
  -b 0.0.0.0:9088 log_intel.wsgi:application
```

Open **http://localhost:9088/** — on first visit, complete **Settings** if prompted.

### LLM setup menu (`./install.sh`)

| Choice | Chat | Embeddings (large files) |
|--------|------|---------------------------|
| **Berget AI** | api.berget.ai | api.berget.ai |
| **Grok / xAI** | api.x.ai | local Ollama :11435 |
| **OpenAI / compatible** [default] | your API | local Ollama :11435 |
| **All-local Ollama** | your Ollama host | same host |

Non-interactive:

```bash
LOG_INTEL_LLM_SETUP=ollama LOG_INTEL_OLLAMA_BASE_URL='http://192.168.1.10:11434' ./install.sh
LOG_INTEL_LLM_SETUP=berget LOG_INTEL_LLM_API_KEY='…' ./install.sh
LOG_INTEL_SKIP_OLLAMA=1 ./install.sh   # skip embed server install
```

Legacy syslogb env names still work: `SYSLOGB_LLM_SETUP`, `SYSLOGB_LLM_API_KEY`, etc.

### All-local Ollama

After choosing **All-local Ollama**, pull models on that host:

```bash
ollama pull qwen3.6:27b-q8_0
ollama pull nomic-embed-text
```

Set `LOG_INTEL_LLM_ENABLED=1` for **on-demand** hub LLM (`/hub/analysis`). Background batch triage is opt-in: `LOG_INTEL_ANALYSIS_AUTO=1`. Meta rollups: `META_SUMMARY_ENABLED=1`.

## Docker (production)

```bash
cp .env.example .env    # or run ./install.sh first, then docker compose
# Edit .env: LOG_DIRS, auth, OLLAMA_BASE_URL (use host.docker.internal for host Ollama)

docker compose up -d --build
```

Default port map: **9088** (HTTP), **5516→514** (syslog). Mounts `/var/log`, `/var/log/remote`, host **systemd journal**, `./data`, `./geoip`.

Compose loads all settings via `env_file: .env`.

### systemd journal

On any **systemd** host (Ubuntu, Debian, Fedora, RHEL, openSUSE, …), log-intel can tail and search the journal alongside `/var/log` files. Sources appear in the sidebar under **systemd journal**:

- **System journal** — `journal://system`
- **Current boot** — `journal://boot`
- Optional per-unit streams from `JOURNAL_UNITS`

Native install: install `systemd` / ensure `journalctl` is on `PATH`, keep `JOURNAL_ENABLED=1` (default). Read access usually requires membership in `systemd-journal` or `adm`:

```bash
sudo usermod -aG systemd-journal "$USER" && newgrp systemd-journal
```

Docker: the compose file mounts `/run/log/journal`, `/var/log/journal`, and `/etc/machine-id` read-only. Leave `JOURNAL_DIRECTORY` empty so `journalctl` picks the right store (persistent `/var/log/journal` on most servers). Set `JOURNAL_DIRECTORY=/run/log/journal` only if you use volatile journal storage.

Tune filters in **Settings** or `.env`: `JOURNAL_UNITS`, `JOURNAL_PRIORITY`, `JOURNAL_MATCH`, `JOURNAL_BOOT_ONLY`, `JOURNAL_SEARCH_SINCE`.

## Configuration

| Source | Purpose |
|--------|---------|
| `.env` | Bootstrap + Docker; secrets (`FLASK_SECRET_KEY`, `LLM_API_KEY`, passwords) |
| **Settings UI** | Runtime tuning (SQLite `data/analyses.db`) — wins over `.env` for most keys |
| `docker-compose.yml` | Ports, volumes, host paths |

Important variables:

```bash
LOG_DIRS=/var/log,/var/log/remote   # file-tail roots
LOG_RECURSIVE=1                     # nested remote host logs
AUTH_ENABLED=1                      # sign-in required
BRAND_LOGO=branding/syslogb.jpg     # under web/static/
OLLAMA_BASE_URL=http://127.0.0.1:11434
LOG_INTEL_LLM_ENABLED=1             # hub on-demand LLM (/hub/analysis)
LOG_INTEL_ANALYSIS_AUTO=0           # set 1 only if you want hourly background batches
LOG_INTEL_RESERVE_EVENTS_MIST=1000  # minimum Mist events kept when pruning
LOG_INTEL_RESERVE_EVENTS_PALO=0     # optional Palo Alto retention floor
LDAP_ADMIN_GROUP=cn=log-intel-admins,ou=Groups,dc=example,dc=com  # LDAP admins (optional)
```

**Roles:** When auth is enabled, LDAP users in `LDAP_ADMIN_GROUP` (or `LDAP_ADMIN_GROUP_CN`) get **Admin** — analyze, alert edits, settings writes. Everyone else is **Read-only** (search, tail, hub views). Local bootstrap user is always admin.

**Ops:** `./scripts/backup-data.sh` backs up SQLite + GeoIP. Import `config/grafana/log-intel-dashboard.json` for starter panels. `/health` and `/metrics` skip auth for probes.

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for tests and commit workflow.

Migrating from syslogb? Run:

```bash
python3 scripts/sync-syslogb-settings.py
# copies analyses.db settings + use install.sh for fresh installs
```

## Log directories

Default: `/var/log`. For rsyslog remote hosts (Syslog Pusher / Windows):

```bash
LOG_DIRS=/var/log,/var/log/remote
LOG_RECURSIVE=1
```

Optional drop-in: `config/rsyslog/50-log-intel-incoming.conf`

Read access on Linux:

```bash
sudo usermod -aG adm "$USER" && newgrp adm
```

## Production deployment

Use **one gunicorn worker** (background tail + hub ingest + LLM workers are in-process). Increase **threads** for concurrent HTTP/SSE:

```bash
gunicorn -w 1 -k gthread --threads 8 --timeout 600 \
  -b 0.0.0.0:9088 --access-logfile - --error-logfile - \
  log_intel.wsgi:application
```

Example systemd unit: `config/systemd/log-intel.service`

Embed server unit (hybrid setups): `config/systemd/ollama-syslogb.service` → installed as `ollama-log-intel` by `scripts/install-ollama-embed.sh`

## Syslog Pusher (Windows)

Windows hosts forward event logs and file tails to log-intel via **[syslog-pusher/](syslog-pusher/)** — a self-contained WPF app + Windows service (C# / .NET 8).

### Quick install (Windows)

1. Copy **`syslog-pusher/dist/SyslogPusher-0.9.1.exe`** to the server (or build from source — see [syslog-pusher/README.md](syslog-pusher/README.md)).
2. Run the exe → complete the setup wizard.
3. Set destination to your log-intel host, e.g. **`192.168.101.115`** port **`5516`** (UDP or TCP).

Logs appear in the hub live feed and in `/var/log/remote/<hostname>/` if you route through rsyslog instead.

### Build from source (Windows)

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0):

```powershell
cd syslog-pusher
.\scripts\publish.ps1
```

Output: `syslog-pusher\dist\SyslogPusher-0.9.1.exe` (single-file, win-x64, self-contained).

### Pairing tips

- Enable **Only new** on directory watches with large historical logs (e.g. `Pri.log`) to avoid replay bursts after service restart.
- log-intel includes a built-in **SMS Pri logs** timestamp parser for `Pri.log` and `ComLinkApp*.log` — see **Help** on the file logs UI.

## Repository layout

```
log_intel/           Python app (syslogb UI + network hub)
syslog-pusher/       Windows client (C#) — source + dist/SyslogPusher-0.9.1.exe
config/              rsyslog drop-in, systemd units
scripts/             install, migration helpers
```

## Migration from syslogb / loggy / netsyslog / syslogpusher

1. `./install.sh` or Docker deploy
2. `python3 scripts/sync-syslogb-settings.py` — copy your syslogb SQLite settings
3. Copy `syslogb/data/chroma/` → `log-intel/data/chroma/` if you want existing RAG indices
4. Point Palo Alto syslog to log-intel port
5. Deploy Windows clients from `syslog-pusher/dist/SyslogPusher-0.9.1.exe`
6. Stop old containers and standalone repos — [DEPRECATION.md](DEPRECATION.md)

## API

**Hub:** `GET /health`, `GET /api/v1/stream`, `GET /api/v1/flows`, `GET /metrics`

**syslogb:** `/api/files`, `/api/stream`, `/api/search`, analyze and alert routes (unchanged)

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Scripts

| Script | Purpose |
|--------|---------|
| `./install.sh` | Full native install (venv, .env, LLM menu, embed server) |
| `scripts/install-ollama-embed.sh` | Local Ollama on :11435 for RAG (auto-run by install.sh) |
| `scripts/sync-syslogb-settings.py` | Merge syslogb `analyses.db` settings into log-intel |
| `scripts/migration-status.sh` | Check migration / container health |
| `scripts/backup-data.sh` | Timestamped backup of `events.sqlite`, `analyses.db`, GeoIP |

## Compare to syslogb install

| syslogb | log-intel |
|---------|-----------|
| `./install.sh` | `./install.sh` (same LLM menu) |
| `python run.py` | `log-intel` or gunicorn `log_intel.wsgi:application` |
| Port 9080 | Port **9088** |
| File logs only | File logs **+** `/hub` network syslog |
| — | `docker compose up` for container deploy |

The install experience is intended to be **as easy as syslogb** — one script, same LLM choices, optional Docker for production.

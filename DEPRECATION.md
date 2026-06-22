# Deprecation notice

**log-intel** (`~/local-devel/log-intel`) is the unified replacement for:

| Project | Path | Status |
|---------|------|--------|
| **syslogb** | `~/local-devel/syslogb` | **Deprecated** — full app vendored at `log_intel/syslogb/` |
| **loggy** | `~/local-devel/loggy` | **Deprecated** — network ingest + analysis in hub; archive via read-only DB mount |
| **netsyslog** | `~/local-devel/netsyslog` | **Deprecated** — geo flows + PA parsing in hub; archive via read-only DB mount |
| **syslogpusher** | `~/local-devel/syslogpusher` | **Deprecated** — Windows client lives at [`syslog-pusher/`](syslog-pusher/) |

## What moved where

### syslogb (base UI)

- File tail, search, export, LLM/RAG, Chroma, alerts, auth, settings → **`/`** (Flask)
- Alert rules (target) → unified on **`events.sqlite`**; migrate with **`scripts/migrate-alert-rules.py`**
- SQLite `analyses.db` → same **`DATA_DIR`** as hub (`/data` in Docker)

### loggy

- UDP syslog ingest, Palo Alto parsing, Ollama batch → **hub ingest** + **`log_intel/loggy_ported/analysis_service`**
- Hourly cards, meta summaries, trends → **`/hub/analysis`** and **`/hub/api/*`** (wired in v0.9.1)
- Historical logs → optional **`LOGGY_DB_PATH`** read-only mount

### netsyslog

- Geo flow aggregates, great-circle map → **`/hub/geo`** and **`/api/v1/flows`**
- Historical events → optional **`NETSYSLOG_DB_PATH`** read-only mount

### syslogpusher (Windows client)

- WPF wizard, Windows service, file/event collectors → **`syslog-pusher/`**
- Pre-built binary → **`syslog-pusher/dist/SyslogPusher-0.9.1.exe`**
- Point destination at log-intel syslog port (default host **5516** → container **514**)

## Single deployment

```bash
cd ~/local-devel/log-intel
docker compose up -d --build
```

| Service | URL / port |
|---------|------------|
| File logs UI (syslogb) | http://host:9088/ |
| Network hub UI | http://host:9088/hub |
| Syslog ingest | UDP/TCP **5516** → container **514** (default; avoid conflict with rsyslog/loggy) |
| Metrics | http://host:9088/metrics |

## Cutover checklist

1. Point Palo Alto syslog fan-out to **log-intel :5516** only.
2. Deploy **`syslog-pusher/dist/SyslogPusher-0.9.1.exe`** on Windows hosts (or rebuild from `syslog-pusher/`).
3. Point Syslog Pusher destination to the same log-intel syslog port.
4. Set **`LOG_DIRS`** (or mount `/var/log`) for file-tail if using rsyslog remote files.
5. Stop separate **syslogb**, **loggy**, **netsyslog**, and standalone **syslogpusher** repos/services.
6. Keep old `data/` volumes mounted read-only until archive retention expires.

Original repos are **archived** (read-only on GitHub/Gitea) — kept for rollback reference, not for new deployments.

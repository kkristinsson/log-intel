#!/usr/bin/env python3
"""Merge syslogb SQLite settings into log-intel analyses.db."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

SYSLOGB_DB = Path("/home/kk/local-devel/syslogb/data/analyses.db")
LOG_INTEL_DB = Path("/home/kk/local-devel/log-intel/data/analyses.db")

# Keys always taken from syslogb DB when present.
COPY_FROM_SYSLOGB = {
    "LOG_DIRS",
    "LOG_RECURSIVE",
    "LOG_GLOB",
    "LOG_SKIP_NAMES",
    "SCAN_INTERVAL_SEC",
    "TAIL_BUFFER_SIZE",
    "TAIL_DEFAULT_ORDER",
    "FILE_RECENT_BYTES",
    "SEARCH_MAX_RESULTS",
    "SEARCH_MAX_BYTES_PER_FILE",
    "SEARCH_CASE_SENSITIVE",
    "LLM_PROVIDER",
    "LLM_SKIP_LOW_LEVELS",
    "LLM_MAX_FILE_BYTES",
    "LLM_DIRECT_MAX_BYTES",
    "RAG_CHUNK_LINES",
    "RAG_CHUNK_OVERLAP",
    "RAG_TOP_K",
    "RAG_MAX_LINES",
    "RAG_MAX_CHUNKS",
    "EMBED_BATCH_SIZE",
    "EMBED_MAX_CHARS",
    "EMBED_LINE_MAX_CHARS",
    "EMBED_MAX_RETRIES",
    "RAG_QUERY",
    "OLLAMA_MODEL",
    "OLLAMA_EMBED_MODEL",
    "OLLAMA_EMBED_TIMEOUT_SEC",
    "OLLAMA_NUM_PREDICT",
    "LOG_LINE_MAX_CHARS",
    "BRAND_LOGO",
    "BRAND_LOGO_LINK",
    "BRAND_TAGLINE",
    "COPYRIGHT_TEXT",
}

import os

# Docker-adjusted or .env overrides for log-intel.
OVERRIDES = {
    "APP_NAME": "log-intel",
    "LOG_DIR": "/var/log",
    "LOG_DIRS": "/var/log,/var/log/remote",
    "LOG_RECURSIVE": "1",
    "OLLAMA_BASE_URL": "http://host.docker.internal:11434",
    "OLLAMA_TIMEOUT_SEC": "800",
    "OLLAMA_JSON_FORMAT": "1",
    "AUTH_ENABLED": "1",
    "FLASK_SECRET_KEY": os.environ.get("FLASK_SECRET_KEY", ""),
    "LOCAL_AUTH_USERNAME": os.environ.get("LOCAL_AUTH_USERNAME", "admin"),
    "LOCAL_AUTH_PASSWORD": os.environ.get("LOCAL_AUTH_PASSWORD", ""),
    "BRAND_LOGO": "branding/syslogb.jpg",
    "BRAND_LOGO_LINK": "",
    "BRAND_TAGLINE": "",
    "COPYRIGHT_TEXT": "log-intel by Kristinsson Consulting",
    "FILE_RECENT_BYTES": "524288",
    "SEARCH_MAX_RESULTS": "2000",
    "SEARCH_MAX_BYTES_PER_FILE": "5242880",
    "SETUP_COMPLETE": "1",
    "DATA_DIR": "/data",
    "FLASK_PORT": "9088",
}


def main() -> None:
    if not SYSLOGB_DB.is_file():
        raise SystemExit(f"missing {SYSLOGB_DB}")
    if not LOG_INTEL_DB.is_file():
        raise SystemExit(f"missing {LOG_INTEL_DB}")

    src = sqlite3.connect(SYSLOGB_DB)
    dst = sqlite3.connect(LOG_INTEL_DB)
    now = time.time()
    updated = 0

    src_rows = {
        row[0]: (row[1], row[2])
        for row in src.execute("SELECT key, value, value_type FROM settings")
    }

    for key in COPY_FROM_SYSLOGB:
        if key in src_rows:
            value, vtype = src_rows[key]
            dst.execute(
                """
                INSERT INTO settings (key, value, value_type, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    value_type=excluded.value_type,
                    updated_at=excluded.updated_at
                """,
                (key, value, vtype, now),
            )
            updated += 1

    for key, value in OVERRIDES.items():
        vtype = src_rows.get(key, (None, "str"))[1] if key in src_rows else "str"
        if key in ("AUTH_ENABLED", "LOG_RECURSIVE", "OLLAMA_JSON_FORMAT"):
            vtype = "bool"
        if key in ("SEARCH_MAX_RESULTS", "FILE_RECENT_BYTES", "SEARCH_MAX_BYTES_PER_FILE", "FLASK_PORT", "OLLAMA_NUM_PREDICT", "OLLAMA_TIMEOUT_SEC", "OLLAMA_EMBED_TIMEOUT_SEC"):
            vtype = "int"
        dst.execute(
            """
            INSERT INTO settings (key, value, value_type, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                value_type=excluded.value_type,
                updated_at=excluded.updated_at
            """,
            (key, value, vtype, now),
        )
        updated += 1

    dst.commit()
    src.close()
    dst.close()
    print(f"Updated {updated} settings in {LOG_INTEL_DB}")


if __name__ == "__main__":
    main()

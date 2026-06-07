#!/usr/bin/env python3
"""One-time migration: syslogb analyses.db alert_rules → hub events.sqlite."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path


def migrate(analyses_db: Path, events_db: Path, *, dry_run: bool) -> int:
    if not analyses_db.is_file():
        print(f"Missing analyses DB: {analyses_db}", file=sys.stderr)
        return 1
    src = sqlite3.connect(analyses_db)
    src.row_factory = sqlite3.Row
    try:
        rows = src.execute(
            """SELECT id, name, enabled, scope, query, mode, log_dir, file_glob,
                      cooldown_sec, webhook_url, email_to
               FROM alert_rules"""
        ).fetchall()
    except sqlite3.OperationalError as e:
        print(f"Cannot read alert_rules from {analyses_db}: {e}", file=sys.stderr)
        return 1
    finally:
        src.close()

    if dry_run:
        print(f"Would migrate {len(rows)} rule(s) to {events_db}")
        for r in rows:
            print(f"  - {r['name']} ({r['id']})")
        return 0

    events_db.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(events_db)
    now = time.time()
    migrated = 0
    try:
        for r in rows:
            dst.execute(
                """INSERT INTO alert_rules (
                    id, name, enabled, query, mode, source_type, scope,
                    cooldown_sec, webhook_url, email_to, log_dir, file_glob,
                    created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  name=excluded.name, enabled=excluded.enabled, query=excluded.query,
                  mode=excluded.mode, scope=excluded.scope, cooldown_sec=excluded.cooldown_sec,
                  webhook_url=excluded.webhook_url, email_to=excluded.email_to,
                  log_dir=excluded.log_dir, file_glob=excluded.file_glob,
                  updated_at=excluded.updated_at""",
                (
                    r["id"],
                    r["name"],
                    int(r["enabled"]),
                    r["query"],
                    r["mode"],
                    None,
                    r["scope"],
                    int(r["cooldown_sec"] or 300),
                    r["webhook_url"],
                    r["email_to"],
                    r["log_dir"],
                    r["file_glob"],
                    now,
                    now,
                ),
            )
            migrated += 1
        dst.commit()
    finally:
        dst.close()

    print(f"Migrated {migrated} alert rule(s) → {events_db}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--analyses-db", type=Path, default=Path("./data/analyses.db"))
    p.add_argument("--events-db", type=Path, default=Path("./data/events.sqlite"))
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    return migrate(args.analyses_db, args.events_db, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())

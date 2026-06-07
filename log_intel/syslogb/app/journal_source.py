"""systemd journal virtual log sources (journalctl — works on any systemd distro)."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from log_intel.syslogb.app import config

logger = logging.getLogger(__name__)

JOURNAL_PREFIX = "journal://"


@dataclass(frozen=True)
class JournalSpec:
    """Virtual source id, e.g. journal://system or journal://boot."""

    uri: str
    boot_only: bool = False

    @property
    def name(self) -> str:
        if self.uri == "journal://boot":
            return "Current boot"
        if self.uri == "journal://system":
            return "System journal"
        if self.uri.startswith(JOURNAL_PREFIX + "unit/"):
            return self.uri.removeprefix(JOURNAL_PREFIX + "unit/")
        return self.uri.removeprefix(JOURNAL_PREFIX)

    def display_path(self) -> str:
        return self.uri


def is_journal_source(source: str | Path) -> bool:
    return str(source).startswith(JOURNAL_PREFIX)


def parse_journal_uri(uri: str) -> JournalSpec:
    u = uri.strip()
    if not u.startswith(JOURNAL_PREFIX):
        raise ValueError(f"Not a journal URI: {uri}")
    if u == "journal://boot":
        return JournalSpec(uri=u, boot_only=True)
    if u == "journal://system":
        return JournalSpec(uri=u, boot_only=False)
    if u.startswith(JOURNAL_PREFIX + "unit/"):
        return JournalSpec(uri=u, boot_only=False)
    raise ValueError(f"Unknown journal URI: {uri}")


def list_journal_sources() -> list[JournalSpec]:
    if not config.JOURNAL_ENABLED:
        return []
    specs = [JournalSpec("journal://system"), JournalSpec("journal://boot")]
    for unit in _split_csv(config.JOURNAL_UNITS):
        specs.append(JournalSpec(f"{JOURNAL_PREFIX}unit/{unit}"))
    return specs


def _split_csv(raw: str) -> list[str]:
    return [p.strip() for p in (raw or "").split(",") if p.strip()]


def journal_available() -> tuple[bool, str]:
    if not config.JOURNAL_ENABLED:
        return False, "JOURNAL_ENABLED=0"
    if not shutil.which("journalctl"):
        return False, "journalctl not found (non-systemd host?)"
    if config.JOURNAL_DIRECTORY.strip():
        d = Path(config.JOURNAL_DIRECTORY).expanduser()
        if not d.is_dir():
            return False, f"JOURNAL_DIRECTORY not found: {d}"
    try:
        proc = subprocess.run(
            _base_cmd() + ["--no-pager", "-n", "1", "-o", "cat"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "journalctl failed").strip()[:200]
        return False, err
    return True, "OK"


def _base_cmd() -> list[str]:
    cmd = ["journalctl", "--no-pager"]
    jd = config.JOURNAL_DIRECTORY.strip()
    if jd:
        cmd.extend(["--directory", jd])
    if config.JOURNAL_MERGE_SYSTEM:
        cmd.append("--merge")
    return cmd


def journalctl_argv(spec: JournalSpec, *, follow: bool = False, extra: list[str] | None = None) -> list[str]:
    cmd = _base_cmd()
    if spec.boot_only or config.JOURNAL_BOOT_ONLY:
        cmd.append("-b")
    for unit in _units_for_spec(spec):
        cmd.extend(["-u", unit])
    pri = config.JOURNAL_PRIORITY.strip()
    if pri:
        cmd.extend(["--priority", pri])
    for m in _split_csv(config.JOURNAL_MATCH):
        cmd.extend(["--grep", m])
    if follow:
        cmd.extend(["-f", "-n", str(config.JOURNAL_FOLLOW_LINES), "-o", config.JOURNAL_OUTPUT])
    if extra:
        cmd.extend(extra)
    return cmd


def _units_for_spec(spec: JournalSpec) -> list[str]:
    if spec.uri.startswith(JOURNAL_PREFIX + "unit/"):
        return [spec.uri.split("/", 1)[1]]
    return _split_csv(config.JOURNAL_UNITS)


def read_journal_lines(
    spec: JournalSpec,
    *,
    max_lines: int | None = None,
    since: str | None = None,
    until: str | None = None,
    reverse: bool = True,
) -> tuple[list[str], str | None]:
    """Fetch journal lines (non-follow). Returns (lines oldest-first for paging, error)."""
    max_lines = max_lines or config.JOURNAL_PAGE_LINES
    extra: list[str] = ["-o", config.JOURNAL_OUTPUT, "-n", str(max_lines)]
    if reverse:
        extra.append("--reverse")
    if since:
        extra.extend(["--since", since])
    if until:
        extra.extend(["--until", until])
    cmd = journalctl_argv(spec, extra=extra)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=config.JOURNAL_READ_TIMEOUT_SEC)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], str(e)
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout or "journalctl failed").strip()[:500]
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if reverse:
        lines.reverse()
    return lines, None


def journal_sidebar_entry(spec: JournalSpec, *, watching: bool) -> dict[str, Any]:
    return {
        "path": spec.uri,
        "name": spec.name,
        "log_dir": "systemd",
        "log_dir_label": "systemd journal",
        "group_path": "journal://systemd",
        "group_label": "systemd journal",
        "local_subdir": "",
        "watching": watching,
        "readable": True,
        "compressed": False,
        "size_bytes": None,
        "journal": True,
    }

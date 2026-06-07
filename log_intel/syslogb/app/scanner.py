from __future__ import annotations

import fnmatch
import logging
import os
import threading
from pathlib import Path
from typing import Callable, Optional

from log_intel.syslogb.app import config

logger = logging.getLogger(__name__)

_SKIP_NAMES = frozenset(
    n.strip() for n in config.LOG_SKIP_NAMES.split(",") if n.strip()
)

_BINARY_SAMPLE_BYTES = 8192
# Bytes below this ratio of printable ASCII + tab/LF/CR → treat as binary.
_BINARY_MIN_TEXT_RATIO = 0.85


def is_compressed(path: Path) -> bool:
    name = path.name.lower()
    for suffix in config.COMPRESSED_SUFFIXES:
        if name.endswith(suffix):
            return True
    return False


def is_gzip_path(path: Path) -> bool:
    return path.name.lower().endswith(".gz")


def is_compressed_path(path: Path) -> bool:
    return is_compressed(path)


def is_compressed_listable(path: Path) -> bool:
    if not is_compressed(path):
        return False
    return bool(config.LOG_READ_COMPRESSED) and is_gzip_path(path)


def is_skipped_name(path: Path) -> bool:
    return path.name in _SKIP_NAMES


def is_probably_binary(path: Path) -> bool:
    """Heuristic: NUL bytes or mostly non-text in the file head → not a text log."""
    try:
        size = path.stat().st_size
    except OSError:
        return True
    if size == 0:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(min(size, _BINARY_SAMPLE_BYTES))
    except OSError:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    text = sum(1 for b in chunk if b in (9, 10, 13) or 32 <= b < 127)
    return (text / len(chunk)) < _BINARY_MIN_TEXT_RATIO


def should_skip_file(path: Path) -> bool:
    """Skip known binary basenames and content-detected binary files."""
    return is_skipped_name(path) or is_probably_binary(path)


def is_readable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.R_OK)


def is_under_dir(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def is_watchable(path: Path, log_dir: Path) -> bool:
    if path.is_symlink():
        return False
    if not path.is_file():
        return False
    if not is_under_dir(path, log_dir):
        return False
    if is_compressed(path):
        return False
    if should_skip_file(path):
        return False
    if not fnmatch.fnmatch(path.name, config.LOG_GLOB):
        return False
    return is_readable_file(path)


def list_log_files(log_dir: Path, *, watchable_only: bool = False) -> list[Path]:
    if not log_dir.is_dir():
        return []
    root = log_dir.resolve()
    out: list[Path] = []
    try:
        if config.LOG_RECURSIVE:
            candidates = log_dir.rglob("*")
        else:
            candidates = log_dir.iterdir()
        for entry in sorted(candidates):
            resolved = entry.resolve()
            if watchable_only:
                if not is_watchable(resolved, root):
                    continue
            else:
                if entry.is_symlink() or not resolved.is_file():
                    continue
                if not is_under_dir(resolved, root):
                    continue
                if is_compressed(resolved) and not is_compressed_listable(resolved):
                    continue
                if should_skip_file(resolved):
                    continue
                if not fnmatch.fnmatch(resolved.name, config.LOG_GLOB):
                    continue
            out.append(resolved)
    except OSError as e:
        logger.warning("Cannot list %s: %s", log_dir, e)
    return out


class DirectoryScanner:
    """Poll log directory and start/stop tailers as files appear or vanish."""

    def __init__(
        self,
        log_dir: Path,
        on_start: Callable[[Path], None],
        on_stop: Callable[[Path], None],
        interval_sec: float = config.SCAN_INTERVAL_SEC,
    ) -> None:
        self._log_dir = log_dir
        self._on_start = on_start
        self._on_stop = on_stop
        self._interval = interval_sec
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._active: set[Path] = set()

    @property
    def active_files(self) -> set[Path]:
        return set(self._active)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="dir-scanner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._interval + 2)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._scan_once()
            self._stop.wait(self._interval)

    def _scan_once(self) -> None:
        current = set(list_log_files(self._log_dir, watchable_only=True))
        for path in current - self._active:
            logger.info("Watching log file: %s", path)
            self._on_start(path)
            self._active.add(path)
        for path in self._active - current:
            logger.info("Stopped watching: %s", path)
            self._on_stop(path)
            self._active.discard(path)


def check_log_dir_access(log_dir: Path) -> tuple[bool, str]:
    import grp
    import pwd

    if not log_dir.exists():
        return False, f"LOG_DIR does not exist: {log_dir}"
    if not log_dir.is_dir():
        return False, f"LOG_DIR is not a directory: {log_dir}"
    if not os.access(log_dir, os.R_OK):
        return False, (
            f"LOG_DIR is not readable: {log_dir}. "
            "Add your user to the adm group and log in again (or run: newgrp adm)."
        )
    extra = ""
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        extra = f" (user={user}, groups={','.join(groups)})"
    except (KeyError, OSError):
        pass
    return True, f"LOG_DIR OK: {log_dir}{extra}"

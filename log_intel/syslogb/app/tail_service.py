from __future__ import annotations

import json
import logging
import queue
import threading
from pathlib import Path
from typing import Optional

from log_intel.syslogb.app import config
from log_intel.syslogb.app.alert_engine import AlertEngine
from log_intel.syslogb.app.journal_source import (
    journal_available,
    journal_sidebar_entry,
    list_journal_sources,
)
from log_intel.syslogb.app.journal_tailer import JournalTailer
from log_intel.syslogb.app.log_dirs import (
    LOCALHOST_GROUP_LABEL,
    display_name_for_dir,
    group_for_path,
    group_path_key,
    list_log_groups,
    local_subdir_for_path,
    log_dirs,
)
from log_intel.syslogb.app.merge import MergeBuffer
from log_intel.syslogb.app.scanner import DirectoryScanner, check_log_dir_access, is_gzip_path, is_readable_file, list_log_files
from log_intel.syslogb.app.tailer import FileTailer

logger = logging.getLogger(__name__)


class MultiDirectoryScanner:
    def __init__(
        self,
        directories: list[Path],
        on_start,
        on_stop,
    ) -> None:
        self._scanners = [
            DirectoryScanner(d, on_start, on_stop) for d in directories
        ]

    def start(self) -> None:
        for scanner in self._scanners:
            scanner.start()

    def stop(self) -> None:
        for scanner in self._scanners:
            scanner.stop()

    @property
    def active_files(self) -> set[Path]:
        out: set[Path] = set()
        for scanner in self._scanners:
            out |= scanner.active_files
        return out


def check_log_dirs_access(directories: list[Path]) -> tuple[bool, str]:
    if not directories:
        return False, "No log directories configured"
    messages: list[str] = []
    ok_all = True
    for d in directories:
        ok, msg = check_log_dir_access(d)
        messages.append(msg)
        ok_all = ok_all and ok
    return ok_all, " | ".join(messages)


class TailService:
    def __init__(self, alert_engine: AlertEngine | None = None) -> None:
        self._buffer = MergeBuffer(config.TAIL_BUFFER_SIZE)
        self._tailers: dict[Path, FileTailer] = {}
        self._journal_tailers: dict[str, JournalTailer] = {}
        self._lock = threading.Lock()
        self._scanner: MultiDirectoryScanner | None = None
        self._sse_queues: list[queue.Queue] = []
        self._sse_lock = threading.Lock()
        self._alert_engine = alert_engine
        self._journal_ok = False
        self._journal_msg = ""

        self._buffer.subscribe(self._broadcast_event)

    @property
    def buffer(self) -> MergeBuffer:
        return self._buffer

    @property
    def journal_status(self) -> dict[str, str | bool]:
        return {"ok": self._journal_ok, "message": self._journal_msg}

    def _on_failure_line(self, source: str, line: str, ts: Optional[float], received_at: float) -> None:
        self._buffer.push(source, line, ts, received_at)

    def _on_raw_line(self, source: str, line: str, ts: Optional[float], received_at: float) -> None:
        if self._alert_engine:
            self._alert_engine.on_line(source, line, ts, received_at)

    def _broadcast_event(self, event) -> None:
        payload = json.dumps(event.to_dict())
        with self._sse_lock:
            dead: list[queue.Queue] = []
            for q in self._sse_queues:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._sse_queues.remove(q)

    def subscribe_sse(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._sse_lock:
            self._sse_queues.append(q)
        return q

    def unsubscribe_sse(self, q: queue.Queue) -> None:
        with self._sse_lock:
            if q in self._sse_queues:
                self._sse_queues.remove(q)

    def _start_tailer(self, path: Path) -> None:
        with self._lock:
            if path in self._tailers:
                return
            tailer = FileTailer(
                path,
                self._on_failure_line,
                on_raw_line=self._on_raw_line,
            )
            self._tailers[path] = tailer
            tailer.start()

    def _stop_tailer(self, path: Path) -> None:
        with self._lock:
            tailer = self._tailers.pop(path, None)
        if tailer:
            tailer.stop()

    def _start_journal_tailers(self) -> None:
        self._journal_ok, self._journal_msg = journal_available()
        if not self._journal_ok:
            if config.JOURNAL_ENABLED:
                logger.warning("Journal ingest disabled: %s", self._journal_msg)
            return
        for spec in list_journal_sources():
            if spec.uri in self._journal_tailers:
                continue
            tailer = JournalTailer(spec, self._on_failure_line, on_raw_line=self._on_raw_line)
            self._journal_tailers[spec.uri] = tailer
            tailer.start()
        logger.info("Journal tail started (%s sources)", len(self._journal_tailers))

    def _stop_journal_tailers(self) -> None:
        for uri in list(self._journal_tailers.keys()):
            t = self._journal_tailers.pop(uri, None)
            if t:
                t.stop()

    def start(self) -> tuple[bool, str]:
        directories = log_dirs()
        ok, msg = check_log_dirs_access(directories)
        if not ok:
            logger.warning(msg)
        self._scanner = MultiDirectoryScanner(
            directories,
            on_start=self._start_tailer,
            on_stop=self._stop_tailer,
        )
        self._scanner.start()
        self._start_journal_tailers()
        if self._journal_ok:
            msg = f"{msg} | journal OK" if msg else "journal OK"
        return ok, msg

    def stop(self) -> None:
        self._stop_journal_tailers()
        if self._scanner:
            self._scanner.stop()
            self._scanner = None
        with self._lock:
            paths = list(self._tailers.keys())
        for path in paths:
            self._stop_tailer(path)

    def reload(self) -> tuple[bool, str]:
        """Restart scanners/tailers after LOG_DIRS or scan settings change."""
        logger.info("Reloading tail service")
        self.stop()
        self._buffer = MergeBuffer(config.TAIL_BUFFER_SIZE)
        self._buffer.subscribe(self._broadcast_event)
        return self.start()

    def watched_files(self) -> list[dict]:
        watched: set[Path] = set()
        if self._scanner:
            watched = self._scanner.active_files

        entries: list[dict] = []
        if self._journal_ok:
            for spec in list_journal_sources():
                entries.append(
                    journal_sidebar_entry(spec, watching=spec.uri in self._journal_tailers)
                )

        for root in log_dirs():
            root_resolved = root.resolve()
            for p in list_log_files(root):
                readable = is_readable_file(p)
                size_bytes = None
                if readable:
                    try:
                        size_bytes = p.stat().st_size
                    except OSError:
                        size_bytes = None
                grouped = group_for_path(p, root_resolved)
                group_path = group_path_key(grouped[0], grouped[1]) if grouped else ""
                group_label = grouped[1] if grouped else ""
                local_subdir = ""
                if grouped and grouped[1] == LOCALHOST_GROUP_LABEL:
                    local_subdir = local_subdir_for_path(p, root_resolved)
                entries.append({
                    "path": str(p),
                    "name": p.name,
                    "log_dir": str(root_resolved),
                    "log_dir_label": display_name_for_dir(root_resolved),
                    "group_path": group_path,
                    "group_label": group_label,
                    "local_subdir": local_subdir,
                    "watching": p in watched,
                    "readable": readable,
                    "compressed": is_gzip_path(p),
                    "size_bytes": size_bytes,
                })

        entries.sort(
            key=lambda e: (
                e.get("group_label", "").lower(),
                e.get("log_dir_label", "").lower(),
                e.get("name", "").lower(),
            )
        )
        return entries

    def log_groups(self) -> list[dict]:
        groups = list_log_groups()
        if self._journal_ok:
            groups.insert(0, {"path": "journal://systemd", "label": "systemd journal", "count": len(list_journal_sources())})
        return groups

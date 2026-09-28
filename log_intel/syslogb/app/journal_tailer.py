"""Follow systemd journal via journalctl -f."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Callable, Optional

from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.journal_source import JournalSpec, journalctl_argv
from log_intel.syslogb.app.parser import parse_timestamp

logger = logging.getLogger(__name__)


class JournalTailer:
    def __init__(
        self,
        spec: JournalSpec,
        on_failure_line: Callable[[str, str, Optional[float], float], None],
        on_raw_line: Callable[[str, str, Optional[float], float], None] | None = None,
        want_failures: Callable[[], bool] | None = None,
        want_raw: Callable[[], bool] | None = None,
    ) -> None:
        self._spec = spec
        self._source = spec.uri
        self._on_failure_line = on_failure_line
        self._on_raw_line = on_raw_line
        self._want_failures = want_failures
        self._want_raw = want_raw
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: subprocess.Popen[str] | None = None

    @property
    def source(self) -> str:
        return self._source

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name=f"journal-{self._spec.name}",
            daemon=True,
        )
        self._thread.start()

    def _terminate_proc(self) -> None:
        proc = self._proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def stop(self) -> None:
        self._stop.set()
        self._terminate_proc()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=3)

    def _run(self) -> None:
        cmd = journalctl_argv(self._spec, follow=True)
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as e:
            logger.warning("Cannot start journal tail %s: %s", self._source, e)
            return

        assert self._proc.stdout is not None
        logger.info("Journal follow: %s (%s)", self._source, " ".join(cmd))
        try:
            while not self._stop.is_set():
                line = self._proc.stdout.readline()
                if not line:
                    if self._proc.poll() is not None:
                        err = (self._proc.stderr.read() if self._proc.stderr else "")[:300]
                        logger.warning("journalctl exited for %s: %s", self._source, err)
                        break
                    time.sleep(0.2)
                    continue
                line = line.rstrip("\n")
                if not line:
                    continue
                want_raw = bool(self._on_raw_line) and (
                    self._want_raw is None or self._want_raw()
                )
                classify = self._want_failures is None or self._want_failures()
                if not want_raw and not classify:
                    continue
                received_at = time.time()
                if want_raw:
                    self._on_raw_line(self._source, line, None, received_at)
                if not classify:
                    continue
                if is_failure_line(line):
                    ts = parse_timestamp(line, received_at, source=self._source)
                    self._on_failure_line(self._source, line, ts, received_at)
        finally:
            self._stop.set()
            self._terminate_proc()

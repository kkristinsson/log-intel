from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from log_intel.syslogb.app import config
from log_intel.syslogb.app.fail_filter import is_failure_line
from log_intel.syslogb.app.parser import parse_timestamp

logger = logging.getLogger(__name__)

# Kept for tests / callers that imported the old constant.
POLL_INTERVAL_SEC = 1.0


class FileTailer:
    """Follow one log file from end-of-file, handling rotation and truncation."""

    def __init__(
        self,
        path: Path,
        on_failure_line: Callable[[str, str, Optional[float], float], None],
        on_raw_line: Callable[[str, str, Optional[float], float], None] | None = None,
        want_failures: Callable[[], bool] | None = None,
        want_raw: Callable[[], bool] | None = None,
        poll_interval_sec: float | None = None,
    ) -> None:
        self._path = path
        self._on_failure_line = on_failure_line
        self._on_raw_line = on_raw_line
        self._want_failures = want_failures
        self._want_raw = want_raw
        self._poll_interval_sec = (
            poll_interval_sec if poll_interval_sec is not None else config.TAIL_POLL_INTERVAL_SEC
        )
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._inode: Optional[int] = None
        self._offset = 0
        self._fh = None
        self._partial = b""

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name=f"tailer-{self._path.name}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._close()

    def _close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def _open(self, *, at_end: bool) -> bool:
        self._close()
        try:
            import os

            fh = open(self._path, "rb")
            stat = os.fstat(fh.fileno())
            self._inode = stat.st_ino
            if at_end:
                fh.seek(0, 2)
            else:
                fh.seek(0)
            self._offset = fh.tell()
            self._fh = fh
            self._partial = b""
            return True
        except OSError as e:
            logger.warning("Cannot open %s: %s", self._path, e)
            return False

    def _open_at_end(self) -> bool:
        return self._open(at_end=True)

    def _open_at_start(self) -> bool:
        return self._open(at_end=False)

    def _maybe_reopen(self) -> bool:
        import os
        try:
            st = os.stat(self._path)
        except OSError:
            self._close()
            return False

        # File reappeared after missing — treat as new content from the start.
        if self._fh is None:
            return self._open_at_start()

        if st.st_ino != self._inode or st.st_size < self._offset:
            logger.info("Rotation/truncation detected for %s", self._path)
            return self._open_at_start()

        return True

    def _run(self) -> None:
        if not self._open_at_end():
            return
        source = str(self._path)
        while not self._stop.is_set():
            if not self._maybe_reopen():
                self._stop.wait(self._poll_interval_sec)
                continue

            assert self._fh is not None
            try:
                self._fh.seek(self._offset)
                chunk = self._fh.read(65536)
            except OSError as e:
                logger.warning("Read error %s: %s", self._path, e)
                self._close()
                self._stop.wait(self._poll_interval_sec)
                continue

            if not chunk:
                self._stop.wait(self._poll_interval_sec)
                continue

            self._offset += len(chunk)
            data = self._partial + chunk
            lines = data.split(b"\n")
            self._partial = lines.pop()

            want_raw = bool(self._on_raw_line) and (
                self._want_raw is None or self._want_raw()
            )
            classify = self._want_failures is None or self._want_failures()
            if not want_raw and not classify:
                continue

            now = time.time()
            for raw in lines:
                line = raw.decode("utf-8", errors="replace").rstrip("\r")
                if not line:
                    continue
                if want_raw:
                    self._on_raw_line(source, line, None, now)
                if not classify:
                    continue
                if not is_failure_line(line):
                    continue
                ts = parse_timestamp(line, now, source=source)
                self._on_failure_line(source, line, ts, now)

        self._close()

from __future__ import annotations

import itertools
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Iterator, Optional

from log_intel.syslogb.app.parser import sort_key


@dataclass
class TailEvent:
    id: int
    source: str
    line: str
    ts: Optional[float]
    received_at: float

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "line": self.line,
            "ts": self.ts,
            "received_at": self.received_at,
        }

    @property
    def sort_key(self) -> float:
        return sort_key(self.ts, self.received_at)


class MergeBuffer:
    """Thread-safe ring buffer of failure events from all tailers."""

    def __init__(
        self,
        max_size: int,
        on_push: Optional[Callable[[TailEvent], None]] = None,
    ) -> None:
        self._max_size = max_size
        self._on_push = on_push
        self._lock = threading.Lock()
        self._buffer: Deque[TailEvent] = deque(maxlen=max_size)
        self._id_gen = itertools.count(1)
        self._subscribers: list[Callable[[TailEvent], None]] = []

    def subscribe(self, callback: Callable[[TailEvent], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def push(self, source: str, line: str, ts: Optional[float], received_at: float) -> TailEvent:
        event = TailEvent(
            id=next(self._id_gen),
            source=source,
            line=line,
            ts=ts,
            received_at=received_at or time.time(),
        )
        with self._lock:
            self._buffer.append(event)
            callbacks = list(self._subscribers)
        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                pass
        if self._on_push:
            self._on_push(event)
        return event

    def snapshot(self, order: str = "desc", source: str | None = None) -> list[TailEvent]:
        with self._lock:
            items = list(self._buffer)
        if source:
            items = [e for e in items if e.source == source]
        reverse = order != "asc"
        return sorted(items, key=lambda e: e.sort_key, reverse=reverse)

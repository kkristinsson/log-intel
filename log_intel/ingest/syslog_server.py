"""Async syslog UDP/TCP server (adapted from netsyslog)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from log_intel.config import Settings

log = logging.getLogger(__name__)

QueueItem = tuple[bytes, str, str]


class SyslogUDP(asyncio.DatagramProtocol):
    def __init__(
        self,
        queue: asyncio.Queue[QueueItem],
        on_queue_drop: Callable[[str, str], None] | None = None,
    ) -> None:
        self._queue = queue
        self._on_queue_drop = on_queue_drop

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        host = str(addr[0]) if addr else ""
        try:
            self._queue.put_nowait((data, host, "udp"))
        except asyncio.QueueFull:
            log.warning("drop udp syslog queue full from %s", host)
            if self._on_queue_drop:
                self._on_queue_drop(host, "udp")


async def serve_udp(
    queue: asyncio.Queue[QueueItem],
    settings: Settings,
    on_queue_drop: Callable[[str, str], None] | None = None,
) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDP(queue, on_queue_drop),
        local_addr=(settings.syslog_udp_host, settings.syslog_udp_port),
        reuse_port=False,
    )
    log.info(
        "syslog UDP listening on %s:%s",
        settings.syslog_udp_host,
        settings.syslog_udp_port,
    )
    return transport


async def _enqueue(
    queue: asyncio.Queue[QueueItem],
    data: bytes,
    host: str,
    on_queue_drop: Callable[[str, str], None] | None,
) -> None:
    if not data:
        return
    try:
        queue.put_nowait((data, host, "tcp"))
    except asyncio.QueueFull:
        log.warning("drop tcp syslog queue full from %s", host)
        if on_queue_drop:
            on_queue_drop(host, "tcp")


async def _read_octet_frame(reader: asyncio.StreamReader) -> bytes | None:
    """Read one RFC6587 octet-counted frame: MSG-LEN SP SYSLOG-MSG."""
    length_buf = bytearray()
    while True:
        b = await reader.read(1)
        if not b:
            return None if not length_buf else b""
        if b == b" ":
            break
        if not (48 <= b[0] <= 57):  # digits only
            raise ValueError(f"invalid octet frame length byte {b!r}")
        length_buf.extend(b)
        if len(length_buf) > 10:
            raise ValueError("octet frame length too long")
    if not length_buf:
        raise ValueError("empty octet frame length")
    n = int(length_buf.decode("ascii"))
    if n < 0 or n > 1_048_576:
        raise ValueError(f"octet frame length out of range: {n}")
    return await reader.readexactly(n)


async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue[QueueItem],
    framing: str,
    on_queue_drop: Callable[[str, str], None] | None = None,
    *,
    client_slots: asyncio.Semaphore | None = None,
) -> None:
    peer = writer.get_extra_info("peername")
    host = str(peer[0]) if isinstance(peer, tuple) and peer else ""
    acquired = False
    try:
        if client_slots is not None:
            try:
                await asyncio.wait_for(client_slots.acquire(), timeout=0.01)
                acquired = True
            except TimeoutError:
                log.warning("reject tcp syslog client from %s (max clients reached)", host)
                return
        if framing == "octet":
            while True:
                try:
                    frame = await _read_octet_frame(reader)
                except (asyncio.IncompleteReadError, ValueError) as e:
                    if isinstance(e, ValueError):
                        log.warning("octet framing error from %s: %s", host, e)
                    break
                if frame is None:
                    break
                await _enqueue(queue, frame, host, on_queue_drop)
        else:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if line.endswith(b"\n"):
                    line = line[:-1]
                if line.endswith(b"\r"):
                    line = line[:-1]
                await _enqueue(queue, line, host, on_queue_drop)
    finally:
        if acquired and client_slots is not None:
            client_slots.release()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve_tcp(
    queue: asyncio.Queue[QueueItem],
    settings: Settings,
    on_queue_drop: Callable[[str, str], None] | None = None,
) -> asyncio.AbstractServer:
    framing = settings.tcp_framing.lower().strip()
    if framing not in ("line", "octet"):
        log.warning("unknown tcp_framing %r, using line", framing)
        framing = "line"

    max_clients = max(1, int(getattr(settings, "syslog_tcp_max_clients", 64) or 64))
    client_slots = asyncio.Semaphore(max_clients)

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await handle_tcp_client(
            r, w, queue, framing, on_queue_drop, client_slots=client_slots
        )

    server = await asyncio.start_server(
        _handler,
        host=settings.syslog_tcp_host,
        port=settings.syslog_tcp_port,
    )
    log.info(
        "syslog TCP listening on %s:%s framing=%s max_clients=%s",
        settings.syslog_tcp_host,
        settings.syslog_tcp_port,
        framing,
        max_clients,
    )
    return server

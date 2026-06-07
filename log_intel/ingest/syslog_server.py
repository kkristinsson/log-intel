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


async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue[QueueItem],
    framing: str,
    on_queue_drop: Callable[[str, str], None] | None = None,
) -> None:
    peer = writer.get_extra_info("peername")
    host = str(peer[0]) if isinstance(peer, tuple) and peer else ""
    try:
        if framing == "octet":
            log.warning("RFC6587 octet counting not implemented; using newline framing")
        while True:
            line = await reader.readline()
            if not line:
                break
            if line.endswith(b"\n"):
                line = line[:-1]
            if line.endswith(b"\r"):
                line = line[:-1]
            if not line:
                continue
            try:
                queue.put_nowait((line, host, "tcp"))
            except asyncio.QueueFull:
                log.warning("drop tcp syslog queue full from %s", host)
                if on_queue_drop:
                    on_queue_drop(host, "tcp")
    finally:
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

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await handle_tcp_client(r, w, queue, framing, on_queue_drop)

    server = await asyncio.start_server(
        _handler,
        host=settings.syslog_tcp_host,
        port=settings.syslog_tcp_port,
    )
    log.info(
        "syslog TCP listening on %s:%s framing=%s",
        settings.syslog_tcp_host,
        settings.syslog_tcp_port,
        framing,
    )
    return server

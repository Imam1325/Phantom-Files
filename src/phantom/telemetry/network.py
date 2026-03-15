"""
Network telemetry collector.
"""

from __future__ import annotations

import asyncio
import socket
from typing import List, Optional

from phantom.core.state import NetworkConnection, NetworkInfo


class NetworkCollector:
    async def collect(self, pid: int) -> Optional[NetworkInfo]:
        return await asyncio.to_thread(self._collect_sync, pid)

    def _collect_sync(self, pid: int) -> Optional[NetworkInfo]:
        try:
            import psutil  # type: ignore
        except Exception:
            try:
                return NetworkInfo(local_addr=socket.gethostname())
            except Exception:
                return None

        connections: List[NetworkConnection] = []
        try:
            proc = psutil.Process(pid)
            for conn in proc.connections(kind="inet"):
                protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                connections.append(
                    NetworkConnection(
                        local_addr=conn.laddr.ip if conn.laddr else "",
                        local_port=conn.laddr.port if conn.laddr else 0,
                        remote_addr=conn.raddr.ip if conn.raddr else None,
                        remote_port=conn.raddr.port if conn.raddr else None,
                        protocol=protocol,
                        state=str(conn.status),
                        fd=conn.fd,
                    )
                )
        except Exception:
            return None

        if not connections:
            return None

        first = connections[0]
        return NetworkInfo(
            local_addr=first.local_addr,
            local_port=first.local_port,
            remote_addr=first.remote_addr,
            remote_port=first.remote_port,
            protocol=first.protocol,
            state=first.state,
            connections=tuple(connections),
        )


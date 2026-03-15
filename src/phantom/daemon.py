"""
Обёртка сервиса-демона для Phantom.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Awaitable, Callable, Optional

logger = logging.getLogger("phantom.daemon")


class DaemonService:
    def __init__(self, start_fn: Callable[[], Awaitable[int]]) -> None:
        self._start_fn = start_fn
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def run(self) -> int:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(sig, self._request_stop)
            except NotImplementedError:
                pass

        try:
            return self._loop.run_until_complete(self._start_fn())
        finally:
            pending = asyncio.all_tasks(loop=self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()

    def _request_stop(self) -> None:
        if self._loop and self._loop.is_running():
            for task in asyncio.all_tasks(loop=self._loop):
                task.cancel()
            logger.info("Shutdown requested via signal.")


from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Awaitable, Callable

from phantom.core.state import Event

EventCallback = Callable[[Event], Awaitable[None]]
PermissionCallback = Callable[[Event], Awaitable[bool]]


@dataclass(frozen=True)
class SensorHealth:
    name: str
    running: bool
    degraded: bool
    reason: str = ""


class Sensor(abc.ABC):
    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._running = False
        self._degraded = False
        self._reason = ""

    @abc.abstractmethod
    def start(self) -> None:
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        pass

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def health(self) -> SensorHealth:
        return SensorHealth(
            name=self.__class__.__name__,
            running=self._running,
            degraded=self._degraded,
            reason=self._reason,
        )

    async def _emit(self, event: Event) -> None:
        await self._callback(event)

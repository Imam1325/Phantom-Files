"""Тесты TelemetryCollector."""

import asyncio
from datetime import datetime, timezone

from phantom.core.orchestrator import TelemetryCollector
from phantom.core.state import Event, EventType, Severity


def _event(**kwargs) -> Event:
    defaults = {
        "event_type": EventType.FILE_OPEN,
        "target_path": "/tmp/test",
        "process_pid": 999,
        "source_sensor": "fanotify",
        "severity": Severity.HIGH,
        "timestamp": datetime.now(timezone.utc),
    }
    defaults.update(kwargs)
    return Event(**defaults)


def test_collect_returns_tuple():
    async def _run():
        tc = TelemetryCollector()
        result = await tc.collect(_event())
        assert isinstance(result, tuple)
        assert len(result) == 3

    asyncio.run(_run())


def test_collect_without_pid():
    async def _run():
        tc = TelemetryCollector()
        proc, fs, net = await tc.collect(_event(process_pid=None))
        assert proc is None
        assert net is None

    asyncio.run(_run())


def test_collect_initializes_once():
    async def _run():
        tc = TelemetryCollector()
        assert tc._initialized is False
        await tc.collect(_event())
        assert tc._initialized is True
        # Повторный вызов не переинициализирует
        await tc.collect(_event())
        assert tc._initialized is True

    asyncio.run(_run())


def test_noop_returns_none():
    async def _run():
        result = await TelemetryCollector._noop()
        assert result is None

    asyncio.run(_run())

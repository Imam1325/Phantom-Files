"""Расширенные тесты IncidentStore."""

import asyncio
from datetime import datetime, timezone

from phantom.core.incidents import IncidentStore, IncidentRecord
from phantom.core.state import Event, EventType, Severity


def _event(path="/tmp/t", pid=123, **kwargs) -> Event:
    return Event(
        event_type=EventType.FILE_OPEN,
        target_path=path,
        process_pid=pid,
        severity=Severity.HIGH,
        **kwargs,
    )


def test_upsert_creates_incident():
    async def _run():
        store = IncidentStore()
        rec = await store.upsert(_event())
        assert rec.incident_id.startswith("INC-")
        assert rec.event_count == 1

    asyncio.run(_run())


def test_upsert_dedup_same_path_pid():
    async def _run():
        store = IncidentStore(dedup_window_seconds=10.0)
        e = _event()
        r1 = await store.upsert(e)
        r2 = await store.upsert(e)
        assert r1.incident_id == r2.incident_id
        assert r2.event_count == 2

    asyncio.run(_run())


def test_upsert_different_path_different_incident():
    async def _run():
        store = IncidentStore()
        r1 = await store.upsert(_event(path="/tmp/a"))
        r2 = await store.upsert(_event(path="/tmp/b"))
        assert r1.incident_id != r2.incident_id

    asyncio.run(_run())


def test_upsert_different_pid_different_incident():
    async def _run():
        store = IncidentStore()
        r1 = await store.upsert(_event(pid=100))
        r2 = await store.upsert(_event(pid=200))
        assert r1.incident_id != r2.incident_id

    asyncio.run(_run())


def test_upsert_outside_window_new_incident():
    """Событие за пределами окна дедупликации создаёт новый инцидент."""
    async def _run():
        store = IncidentStore(dedup_window_seconds=0.01)
        r1 = await store.upsert(_event())
        await asyncio.sleep(0.05)
        # Новое событие с той же меткой, но за пределами окна
        e2 = _event(timestamp=datetime.now(timezone.utc))
        r2 = await store.upsert(e2)
        assert r1.incident_id != r2.incident_id

    asyncio.run(_run())


def test_all_open():
    async def _run():
        store = IncidentStore()
        await store.upsert(_event(path="/a"))
        await store.upsert(_event(path="/b"))
        records = await store.all_open()
        assert len(records) == 2

    asyncio.run(_run())


def test_max_records_eviction():
    async def _run():
        store = IncidentStore(max_records=3)
        for i in range(5):
            await store.upsert(_event(path=f"/tmp/trap_{i}"))
        records = await store.all_open()
        assert len(records) == 3

    asyncio.run(_run())


def test_dedup_window_update():
    """Проверяем что dedup_window можно менять после создания."""
    store = IncidentStore(dedup_window_seconds=2.0)
    assert store.dedup_window == 2.0
    store.dedup_window = 5.0
    assert store.dedup_window == 5.0


def test_incident_record_to_dict():
    now = datetime.now(timezone.utc)
    rec = IncidentRecord(
        incident_id="INC-test",
        trap_path="/tmp/t",
        pid=123,
        first_seen=now,
        last_seen=now,
        event_count=3,
    )
    d = rec.to_dict()
    assert d["incident_id"] == "INC-test"
    assert d["event_count"] == 3
    assert d["status"] == "open"


def test_incident_record_touch():
    now = datetime.now(timezone.utc)
    rec = IncidentRecord(
        incident_id="INC-test",
        trap_path="/tmp/t",
        pid=123,
        first_seen=now,
        last_seen=now,
    )
    event = _event()
    rec.touch(event)
    assert rec.event_count == 2
    assert rec.last_event_id == event.event_id

import asyncio

from phantom.core.incidents import IncidentStore
from phantom.core.state import Event, EventType, Severity


async def _run() -> None:
    store = IncidentStore(dedup_window_seconds=2.0)
    event = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/t",
        process_pid=123,
        severity=Severity.HIGH,
    )
    rec1 = await store.upsert(event)
    rec2 = await store.upsert(event)
    assert rec1.incident_id == rec2.incident_id
    assert rec2.event_count == 2


def test_incident_dedup() -> None:
    asyncio.run(_run())


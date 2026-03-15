import asyncio

from phantom.core.orchestrator import Orchestrator, OrchestratorConfig
from phantom.core.state import Event, EventType, Severity


async def _run() -> None:
    orch = Orchestrator(OrchestratorConfig(whitelist_process_names={"rsync"}))

    benign = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap1",
        process_name="unknown",
        severity=Severity.INFO,
        raw_data={"benign": True},
    )
    await orch.handle_event(benign)
    assert orch.stats["events_received"] == 0

    whitelisted = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap2",
        process_name="rsync",
        severity=Severity.INFO,
    )
    await orch.handle_event(whitelisted)
    assert orch.stats["events_received"] == 0

    suspicious = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap3",
        process_name="bash",
        severity=Severity.INFO,
    )
    await orch.handle_event(suspicious)
    assert orch.stats["events_received"] == 1


def test_benign_and_whitelist_events_are_ignored() -> None:
    asyncio.run(_run())

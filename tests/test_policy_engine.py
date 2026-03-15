from datetime import datetime, timezone

from phantom.core.orchestrator import DecisionEngine, OrchestratorConfig
from phantom.core.state import Context, Event, EventType, RunMode, Severity


def _context() -> Context:
    event = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap.txt",
        process_pid=1234,
        source_sensor="fanotify",
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
    )
    return Context(event=event, threat_score=1.0)


def test_policy_actions_override_active() -> None:
    cfg = OrchestratorConfig(
        mode=RunMode.ACTIVE,
        policies={
            "default": {
                "description": "custom",
                "actions": ["alert", "collect_forensics", "kill_process"],
            }
        },
    )
    decision = DecisionEngine(cfg).decide(_context())
    assert [a.value for a in decision.actions] == ["alert", "collect_forensics", "kill_process"]


def test_policy_actions_override_dry_run() -> None:
    cfg = OrchestratorConfig(
        mode=RunMode.DRY_RUN,
        policies={
            "dry_run": {
                "description": "dry",
                "actions": ["alert", "collect_forensics"],
            }
        },
    )
    decision = DecisionEngine(cfg).decide(_context())
    assert [a.value for a in decision.actions] == ["alert", "collect_forensics"]

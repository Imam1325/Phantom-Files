"""Тесты интеграции sandbox в forensics."""

import asyncio
import json
from pathlib import Path

import phantom.response.forensics as forensics
from phantom.core.state import Context, Event, EventType, Severity
from phantom.response.sandbox import SandboxResult


class _DummyPrecapture:
    def export_window(self, *args, **kwargs):  # noqa: ANN001,D401
        return False


class _DummySandbox:
    def __init__(self, artifact: Path) -> None:
        self._artifact = artifact

    async def analyze(self, context, params=None):  # noqa: ANN001
        return SandboxResult(
            container_id="cid",
            container_name="sandbox-test",
            exit_code=0,
            logs="ok",
            artifacts=[str(self._artifact)],
            duration_seconds=1.0,
            timed_out=False,
        )


def test_forensics_collect_sandbox(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("payload", encoding="utf-8")

    cfg = {
        "forensics": {
            "timeout_seconds": 5,
            "pcap_precapture": {"enabled": False},
        },
        "sandbox": {"enabled": True},
        "signing": {},
    }
    monkeypatch.setattr(forensics, "get_path", lambda name: str(tmp_path))
    monkeypatch.setattr(forensics, "get_config", lambda: cfg)
    monkeypatch.setattr(forensics, "get_precapture_manager", lambda _cfg: _DummyPrecapture())
    monkeypatch.setattr(forensics, "SandboxRunner", lambda: _DummySandbox(artifact))

    collector = forensics.ForensicsCollector()
    event = Event(
        event_type=EventType.FILE_OPEN,
        target_path=str(tmp_path / "target.bin"),
        source_sensor="fanotify",
        severity=Severity.HIGH,
    )
    ctx = Context(event=event, threat_score=1.0)
    work = tmp_path / "work"
    work.mkdir()

    asyncio.run(collector._collect_sandbox(ctx, work, deadline=9999999999.0, params={}))

    result_path = work / "sandbox" / "result.json"
    assert result_path.exists()
    data = json.loads(result_path.read_text(encoding="utf-8"))
    assert data["container_name"] == "sandbox-test"
    copied = work / "sandbox" / "artifact.txt"
    assert copied.exists()
    assert copied.read_text(encoding="utf-8") == "payload"

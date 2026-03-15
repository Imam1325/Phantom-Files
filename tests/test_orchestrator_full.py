"""Расширенные тесты оркестратора."""

import asyncio
from datetime import datetime, timezone

from phantom.core.orchestrator import (
    DecisionEngine,
    Orchestrator,
    OrchestratorConfig,
    ThreatAnalyzer,
)
from phantom.core.state import (
    Context, Event, EventType, ProcessInfo, RunMode, Severity, ThreatCategory,
)


def _event(**kwargs) -> Event:
    defaults = {
        "event_type": EventType.FILE_OPEN,
        "target_path": "/tmp/trap.txt",
        "process_pid": 1234,
        "source_sensor": "fanotify",
        "severity": Severity.CRITICAL,
        "timestamp": datetime.now(timezone.utc),
    }
    defaults.update(kwargs)
    return Event(**defaults)


def _context(**kwargs) -> Context:
    defaults = {"event": _event(), "threat_score": 1.0}
    defaults.update(kwargs)
    return Context(**defaults)


# ---------- ThreatAnalyzer ----------

def test_analyzer_whitelist():
    cfg = OrchestratorConfig(whitelist_process_names={"systemd"})
    analyzer = ThreatAnalyzer(cfg)
    proc = ProcessInfo(pid=1, ppid=0, name="systemd")
    category, score, indicators = analyzer.analyze(_event(), proc)
    assert category == ThreatCategory.UNKNOWN
    assert score == 0.0
    assert "whitelist_process" in indicators


def test_analyzer_suspicious_process():
    cfg = OrchestratorConfig()
    analyzer = ThreatAnalyzer(cfg)
    proc = ProcessInfo(pid=1234, ppid=1, name="curl")
    _, score, indicators = analyzer.analyze(_event(), proc)
    assert score > 0.75  # Базовый score + suspicious_process бонус
    assert any("suspicious_process" in i for i in indicators)


def test_analyzer_trap_indicator():
    cfg = OrchestratorConfig()
    analyzer = ThreatAnalyzer(cfg)
    event = _event(trap_id="TRAP-001")
    _, score, indicators = analyzer.analyze(event, None)
    assert score >= 0.95
    assert any("trap:" in i for i in indicators)


def test_analyzer_write_event_persistence():
    cfg = OrchestratorConfig()
    analyzer = ThreatAnalyzer(cfg)
    event = _event(event_type=EventType.FILE_WRITE)
    category, _, _ = analyzer.analyze(event, None)
    assert category == ThreatCategory.PERSISTENCE


def test_analyzer_delete_event_persistence():
    cfg = OrchestratorConfig()
    analyzer = ThreatAnalyzer(cfg)
    event = _event(event_type=EventType.FILE_DELETE)
    category, _, _ = analyzer.analyze(event, None)
    assert category == ThreatCategory.PERSISTENCE


def test_analyzer_no_process():
    cfg = OrchestratorConfig()
    analyzer = ThreatAnalyzer(cfg)
    category, score, indicators = analyzer.analyze(_event(), None)
    assert score > 0.0


# ---------- DecisionEngine ----------

def test_decision_active_default_actions():
    cfg = OrchestratorConfig(mode=RunMode.ACTIVE)
    decision = DecisionEngine(cfg).decide(_context())
    action_values = [a.value for a in decision.actions]
    assert "alert" in action_values
    assert "isolate_process" in action_values
    assert "kill_process" in action_values


def test_decision_observation_adds_forensics():
    cfg = OrchestratorConfig(mode=RunMode.OBSERVATION)
    decision = DecisionEngine(cfg).decide(_context())
    action_values = [a.value for a in decision.actions]
    assert "collect_forensics" in action_values


def test_decision_dry_run_adds_forensics():
    cfg = OrchestratorConfig(mode=RunMode.DRY_RUN)
    decision = DecisionEngine(cfg).decide(_context())
    action_values = [a.value for a in decision.actions]
    assert "collect_forensics" in action_values


def test_decision_mode_in_rationale():
    cfg = OrchestratorConfig(mode=RunMode.ACTIVE)
    decision = DecisionEngine(cfg).decide(_context())
    assert "mode=active" in decision.rationale


def test_decision_from_dict():
    data = {
        "mode": "observation",
        "worker_count": 2,
        "event_queue_size": 100,
    }
    cfg = OrchestratorConfig.from_dict(data)
    assert cfg.mode == RunMode.OBSERVATION
    assert cfg.worker_count == 2
    assert cfg.event_queue_size == 100


def test_decision_dry_run_from_dict():
    data = {"mode": "dry-run"}
    cfg = OrchestratorConfig.from_dict(data)
    assert cfg.mode == RunMode.DRY_RUN


def test_decision_dry_run_underscore():
    data = {"mode": "dry_run"}
    cfg = OrchestratorConfig.from_dict(data)
    assert cfg.mode == RunMode.DRY_RUN


# ---------- Orchestrator ----------

def test_orchestrator_stats_initial():
    orch = Orchestrator()
    stats = orch.stats
    assert stats["events_received"] == 0
    assert stats["events_processed"] == 0
    assert stats["mode"] == "active"


def test_orchestrator_start_stop():
    async def _run():
        orch = Orchestrator()
        await orch.start()
        assert orch._running is True
        await orch.stop()
        assert orch._running is False

    asyncio.run(_run())


def test_orchestrator_handle_benign_event():
    async def _run():
        orch = Orchestrator()
        await orch.start()
        event = _event(raw_data={"benign": True})
        await orch.handle_event(event)
        assert orch.stats["events_received"] == 0
        await orch.stop()

    asyncio.run(_run())


def test_orchestrator_handle_whitelisted():
    async def _run():
        cfg = OrchestratorConfig(whitelist_process_names={"safe_proc"})
        orch = Orchestrator(cfg)
        await orch.start()
        event = _event(process_name="safe_proc")
        await orch.handle_event(event)
        assert orch.stats["events_received"] == 0
        await orch.stop()

    asyncio.run(_run())


def test_orchestrator_severity_filter():
    async def _run():
        cfg = OrchestratorConfig(min_severity=Severity.CRITICAL)
        orch = Orchestrator(cfg)
        await orch.start()
        event = _event(severity=Severity.LOW)
        await orch.handle_event(event)
        # Дождёмся обработки
        await asyncio.sleep(0.05)
        assert orch.stats["events_filtered_severity"] == 1
        await orch.stop()

    asyncio.run(_run())


def test_orchestrator_pre_authorize_whitelist():
    async def _run():
        cfg = OrchestratorConfig(whitelist_process_names={"allowed"})
        orch = Orchestrator(cfg)
        event = _event(process_name="allowed")
        assert await orch.pre_authorize(event) is True

    asyncio.run(_run())


def test_orchestrator_pre_authorize_observation_allows():
    async def _run():
        cfg = OrchestratorConfig(mode=RunMode.OBSERVATION)
        orch = Orchestrator(cfg)
        event = _event(process_name="attacker")
        assert await orch.pre_authorize(event) is True

    asyncio.run(_run())


def test_orchestrator_pre_authorize_active_denies():
    async def _run():
        cfg = OrchestratorConfig(mode=RunMode.ACTIVE, fail_close=True)
        orch = Orchestrator(cfg)
        event = _event(process_name="attacker")
        assert await orch.pre_authorize(event) is False

    asyncio.run(_run())


def test_orchestrator_pre_authorize_no_fail_close():
    async def _run():
        cfg = OrchestratorConfig(mode=RunMode.ACTIVE, fail_close=False)
        orch = Orchestrator(cfg)
        event = _event(process_name="attacker")
        assert await orch.pre_authorize(event) is True

    asyncio.run(_run())


def test_orchestrator_reload_preserves_incidents():
    async def _run():
        orch = Orchestrator()
        await orch.start()
        # Вставляем событие
        event = _event()
        await orch.handle_event(event)
        await asyncio.sleep(0.1)
        # Запоминаем инциденты
        incidents_before = await orch._incidents.all_open()
        count_before = len(incidents_before)
        # Перезагрузка
        await orch.reload_settings({"orchestrator": {"mode": "active"}})
        incidents_after = await orch._incidents.all_open()
        # Инциденты должны сохраниться
        assert len(incidents_after) == count_before
        await orch.stop()

    asyncio.run(_run())


def test_orchestrator_subscribe_decisions():
    decisions_received = []

    async def _callback(decision):
        decisions_received.append(decision)

    async def _run():
        cfg = OrchestratorConfig(mode=RunMode.DRY_RUN)
        orch = Orchestrator(cfg)
        orch.subscribe_decisions(_callback)
        await orch.start()
        event = _event()
        await orch.handle_event(event)
        await asyncio.sleep(0.3)
        await orch.stop()
        assert len(decisions_received) > 0

    asyncio.run(_run())


def test_orchestrator_sensor_degraded():
    orch = Orchestrator()
    orch.set_sensor_degraded(True)
    assert orch._sensor_degraded is True
    orch.set_sensor_degraded(False)
    assert orch._sensor_degraded is False

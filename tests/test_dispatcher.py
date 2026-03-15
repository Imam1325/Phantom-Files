"""Тесты Dispatcher (response/dispatcher.py)."""

import asyncio
from datetime import datetime, timezone

from phantom.core.state import (
    Context, Decision, Event, EventType, NetworkConnection, NetworkInfo,
    ResponseAction, RunMode, Severity,
)
from phantom.response.dispatcher import Dispatcher


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


def _decision(actions: tuple, mode: RunMode = RunMode.ACTIVE, **kwargs) -> Decision:
    if "context" in kwargs:
        ctx = kwargs.pop("context")
    else:
        ctx = Context(event=_event(**kwargs.pop("event_kwargs", {})), threat_score=1.0)
    return Decision.from_context(
        context=ctx,
        actions=actions,
        rationale="test",
        auto_execute=True,
        action_params=kwargs.pop("action_params", {"act_timeout_seconds": 60}),
        mode=mode,
    )


# ---------- _action_blocked_by_mode ----------

def test_action_blocked_by_dry_run():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.KILL_PROCESS, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.BLOCK_NETWORK, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.BLOCK_IP, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.ISOLATE_PROCESS, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.QUARANTINE_FILE, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.SCAN_PERSISTENCE, RunMode.DRY_RUN) is True
    assert d._action_blocked_by_mode(ResponseAction.KILL_USER_SESSIONS, RunMode.DRY_RUN) is True


def test_action_blocked_by_observation():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.KILL_PROCESS, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.ISOLATE_PROCESS, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.BLOCK_NETWORK, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.BLOCK_IP, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.QUARANTINE_FILE, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.SCAN_PERSISTENCE, RunMode.OBSERVATION) is True
    assert d._action_blocked_by_mode(ResponseAction.KILL_USER_SESSIONS, RunMode.OBSERVATION) is True


def test_action_not_blocked_in_active():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.KILL_PROCESS, RunMode.ACTIVE) is False
    assert d._action_blocked_by_mode(ResponseAction.ALERT, RunMode.ACTIVE) is False
    assert d._action_blocked_by_mode(ResponseAction.BLOCK_NETWORK, RunMode.ACTIVE) is False


def test_log_only_allowed_in_all_modes():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.LOG_ONLY, RunMode.DRY_RUN) is False
    assert d._action_blocked_by_mode(ResponseAction.LOG_ONLY, RunMode.OBSERVATION) is False
    assert d._action_blocked_by_mode(ResponseAction.LOG_ONLY, RunMode.ACTIVE) is False


def test_alert_allowed_in_all_modes():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.ALERT, RunMode.DRY_RUN) is False
    assert d._action_blocked_by_mode(ResponseAction.ALERT, RunMode.OBSERVATION) is False


def test_collect_forensics_allowed_in_all_modes():
    d = Dispatcher()
    assert d._action_blocked_by_mode(ResponseAction.COLLECT_FORENSICS, RunMode.DRY_RUN) is False
    assert d._action_blocked_by_mode(ResponseAction.COLLECT_FORENSICS, RunMode.OBSERVATION) is False


# ---------- execute ----------

def test_log_only_action():
    async def _run():
        d = Dispatcher()
        decision = _decision((ResponseAction.LOG_ONLY,))
        await d.execute(decision)

    asyncio.run(_run())


def test_alert_action():
    async def _run():
        d = Dispatcher()
        decision = _decision((ResponseAction.ALERT,))
        await d.execute(decision)

    asyncio.run(_run())


def test_execute_multiple_actions():
    """execute() обрабатывает несколько действий последовательно."""
    async def _run():
        d = Dispatcher()
        decision = _decision((ResponseAction.LOG_ONLY, ResponseAction.ALERT))
        await d.execute(decision)

    asyncio.run(_run())


# ---------- individual handlers ----------

def test_isolate_returns_blocked_by_mode_in_observation():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.ISOLATE_PROCESS,),
            mode=RunMode.OBSERVATION,
        )
        result = await d._isolate_process(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_kill_returns_blocked_by_mode_in_dry_run():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.KILL_PROCESS,),
            mode=RunMode.DRY_RUN,
        )
        result = await d._kill_process(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_kill_no_pid():
    async def _run():
        ctx = Context(event=_event(process_pid=None), threat_score=1.0)
        decision = _decision(
            (ResponseAction.KILL_PROCESS,),
            context=ctx,
        )
        d = Dispatcher()
        result = await d._kill_process(decision)
        assert result.success is False
        assert result.message == "no_pid"

    asyncio.run(_run())


def test_isolate_no_pid():
    async def _run():
        ctx = Context(event=_event(process_pid=None), threat_score=1.0)
        decision = _decision(
            (ResponseAction.ISOLATE_PROCESS,),
            context=ctx,
        )
        d = Dispatcher()
        result = await d._isolate_process(decision)
        assert result.success is False
        assert result.message == "no_pid"

    asyncio.run(_run())


def test_block_ip_blocked_in_observation():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.BLOCK_IP,),
            mode=RunMode.OBSERVATION,
        )
        result = await d._block_ip(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_block_network_blocked_in_dry_run():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.BLOCK_NETWORK,),
            mode=RunMode.DRY_RUN,
        )
        result = await d._block_network(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_quarantine_blocked_in_observation():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.QUARANTINE_FILE,),
            mode=RunMode.OBSERVATION,
        )
        result = await d._quarantine_file(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_quarantine_no_target_path():
    async def _run():
        ctx = Context(event=_event(target_path=""), threat_score=1.0)
        decision = _decision(
            (ResponseAction.QUARANTINE_FILE,),
            context=ctx,
        )
        d = Dispatcher()
        result = await d._quarantine_file(decision)
        assert result.success is False
        assert result.message == "no_target_path"

    asyncio.run(_run())


def test_scan_persistence_blocked_in_dry_run():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.SCAN_PERSISTENCE,),
            mode=RunMode.DRY_RUN,
        )
        result = await d._scan_persistence(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_scan_persistence_no_pid():
    async def _run():
        ctx = Context(event=_event(process_pid=None), threat_score=1.0)
        decision = _decision(
            (ResponseAction.SCAN_PERSISTENCE,),
            context=ctx,
        )
        d = Dispatcher()
        result = await d._scan_persistence(decision)
        assert result.success is False
        assert result.message == "no_pid"

    asyncio.run(_run())


def test_kill_user_sessions_blocked_in_observation():
    async def _run():
        d = Dispatcher()
        decision = _decision(
            (ResponseAction.KILL_USER_SESSIONS,),
            mode=RunMode.OBSERVATION,
        )
        result = await d._kill_user_sessions(decision)
        assert result.success is True
        assert result.message == "blocked_by_mode"

    asyncio.run(_run())


def test_kill_user_sessions_no_pid():
    async def _run():
        ctx = Context(event=_event(process_pid=None), threat_score=1.0)
        decision = _decision(
            (ResponseAction.KILL_USER_SESSIONS,),
            context=ctx,
        )
        d = Dispatcher()
        result = await d._kill_user_sessions(decision)
        assert result.success is False
        assert result.message == "no_pid"

    asyncio.run(_run())


# ---------- _log_only ----------

def test_log_only_result():
    async def _run():
        d = Dispatcher()
        decision = _decision((ResponseAction.LOG_ONLY,))
        result = await d._log_only(decision)
        assert result.success is True
        assert result.action == ResponseAction.LOG_ONLY
        assert "log_only" in result.message

    asyncio.run(_run())


# ---------- _extract_ips ----------

def test_extract_ips_no_network():
    d = Dispatcher()
    decision = _decision((ResponseAction.BLOCK_NETWORK,))
    ips = d._extract_ips(decision)
    assert ips == []


def test_extract_ips_with_connections():
    d = Dispatcher()
    net = NetworkInfo(connections=(
        NetworkConnection(local_addr="10.0.0.1", local_port=22, remote_addr="192.168.1.100", remote_port=55000),
        NetworkConnection(local_addr="10.0.0.1", local_port=22, remote_addr="10.0.0.50", remote_port=55001),
    ))
    ctx = Context(event=_event(), threat_score=1.0, network=net)
    decision = _decision((ResponseAction.BLOCK_NETWORK,), context=ctx)
    ips = d._extract_ips(decision)
    assert "192.168.1.100" in ips
    assert "10.0.0.50" in ips


def test_extract_ips_skips_loopback():
    d = Dispatcher()
    net = NetworkInfo(connections=(
        NetworkConnection(local_addr="10.0.0.1", local_port=80, remote_addr="127.0.0.1", remote_port=1234),
        NetworkConnection(local_addr="10.0.0.1", local_port=80, remote_addr="::1", remote_port=1235),
        NetworkConnection(local_addr="10.0.0.1", local_port=80, remote_addr="0.0.0.0", remote_port=1236),
    ))
    ctx = Context(event=_event(), threat_score=1.0, network=net)
    decision = _decision((ResponseAction.BLOCK_NETWORK,), context=ctx)
    ips = d._extract_ips(decision)
    assert ips == []


def test_extract_ips_deduplicates():
    d = Dispatcher()
    net = NetworkInfo(connections=(
        NetworkConnection(local_addr="10.0.0.1", local_port=22, remote_addr="192.168.1.1", remote_port=100),
        NetworkConnection(local_addr="10.0.0.1", local_port=80, remote_addr="192.168.1.1", remote_port=200),
    ))
    ctx = Context(event=_event(), threat_score=1.0, network=net)
    decision = _decision((ResponseAction.BLOCK_NETWORK,), context=ctx)
    ips = d._extract_ips(decision)
    assert ips == ["192.168.1.1"]


# ---------- handlers coverage ----------

def test_all_response_actions_have_handlers():
    """Все ResponseAction имеют обработчик в Dispatcher."""
    d = Dispatcher()
    for action in ResponseAction:
        assert action in d._handlers, f"Missing handler for {action.value}"

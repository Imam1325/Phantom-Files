"""Тесты модуля state.py (типы данных и перечисления)."""

from datetime import datetime, timezone

from phantom.core.state import (
    Context, Decision, Event, EventType, ProcessInfo, NetworkInfo, NetworkConnection, ResponseAction, ResponseResult,
    RunMode, Severity, ThreatCategory, generate_incident_id,
)


def _event(**kwargs) -> Event:
    defaults = {
        "event_type": EventType.FILE_OPEN,
        "target_path": "/tmp/test.txt",
        "process_pid": 100,
        "source_sensor": "fanotify",
        "severity": Severity.HIGH,
        "timestamp": datetime.now(timezone.utc),
    }
    defaults.update(kwargs)
    return Event(**defaults)


# ---------- Event ----------

def test_event_creation():
    e = _event()
    assert e.event_type == EventType.FILE_OPEN
    assert e.process_pid == 100


def test_event_default_values():
    e = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/t",
        source_sensor="inotify",
    )
    assert e.process_pid is None
    assert e.trap_id is None
    assert e.process_name is None


def test_event_id_generated():
    e = _event()
    assert e.event_id is not None
    assert len(e.event_id) > 0


def test_event_to_dict():
    e = _event()
    d = e.to_dict()
    assert d["event_type"] == "file_open"
    assert d["target_path"] == "/tmp/test.txt"


def test_event_severity_ordering():
    assert Severity.INFO.value < Severity.LOW.value
    assert Severity.LOW.value < Severity.MEDIUM.value
    assert Severity.MEDIUM.value < Severity.HIGH.value
    assert Severity.HIGH.value < Severity.CRITICAL.value


# ---------- Context ----------

def test_context_defaults():
    ctx = Context(event=_event(), threat_score=0.5)
    assert ctx.process is None
    assert ctx.file is None
    assert ctx.network is None
    assert ctx.incident_id is None
    assert ctx.event_count == 1


def test_context_to_dict():
    ctx = Context(
        event=_event(),
        threat_score=0.9,
        threat_category=ThreatCategory.PERSISTENCE,
    )
    d = ctx.to_dict()
    assert d["threat_score"] == 0.9
    assert d["threat_category"] == "persistence"


# ---------- Decision ----------

def test_decision_from_context():
    ctx = Context(event=_event(), threat_score=1.0)
    decision = Decision.from_context(
        context=ctx,
        actions=(ResponseAction.ALERT, ResponseAction.KILL_PROCESS),
        rationale="test reason",
        auto_execute=True,
        action_params={"block_ttl_seconds": 3600},
        mode=RunMode.ACTIVE,
    )
    assert decision.decision_id is not None
    assert decision.mode == RunMode.ACTIVE
    assert len(decision.actions) == 2
    assert decision.rationale == "test reason"


def test_decision_to_dict():
    ctx = Context(event=_event(), threat_score=1.0)
    decision = Decision.from_context(
        context=ctx,
        actions=(ResponseAction.ALERT,),
        rationale="test",
        auto_execute=False,
        action_params={},
        mode=RunMode.DRY_RUN,
    )
    d = decision.to_dict()
    assert d["mode"] == "dry_run"
    assert d["auto_execute"] is False


# ---------- ResponseResult ----------

def test_response_result():
    r = ResponseResult(
        decision_id="DEC-123",
        action=ResponseAction.KILL_PROCESS,
        success=True,
        message="ok",
    )
    assert r.success is True
    assert r.error is None


def test_response_result_with_error():
    r = ResponseResult(
        decision_id="DEC-123",
        action=ResponseAction.BLOCK_IP,
        success=False,
        message="fail",
        error="timeout",
    )
    assert r.success is False
    assert r.error == "timeout"


# ---------- Enum values ----------

def test_event_types():
    assert EventType.FILE_OPEN.value == "file_open"
    assert EventType.FILE_WRITE.value == "file_write"
    assert EventType.FILE_DELETE.value == "file_delete"
    assert EventType.FILE_RENAME.value == "file_rename"


def test_run_modes():
    assert RunMode.ACTIVE.value == "active"
    assert RunMode.OBSERVATION.value == "observation"
    assert RunMode.DRY_RUN.value == "dry_run"


def test_response_actions():
    assert ResponseAction.LOG_ONLY.value == "log_only"
    assert ResponseAction.ALERT.value == "alert"
    assert ResponseAction.COLLECT_FORENSICS.value == "collect_forensics"
    assert ResponseAction.ISOLATE_PROCESS.value == "isolate_process"
    assert ResponseAction.BLOCK_NETWORK.value == "block_network"
    assert ResponseAction.BLOCK_IP.value == "block_ip"
    assert ResponseAction.KILL_PROCESS.value == "kill_process"


def test_threat_categories():
    assert ThreatCategory.RECONNAISSANCE.value == "reconnaissance"
    assert ThreatCategory.PERSISTENCE.value == "persistence"


# ---------- ProcessInfo ----------

def test_process_info():
    p = ProcessInfo(pid=1234, ppid=1, name="bash")
    assert p.name == "bash"
    assert p.pid == 1234


# ---------- NetworkInfo ----------

def test_network_connection():
    conn = NetworkConnection(
        local_addr="0.0.0.0",
        local_port=50000,
        remote_addr="10.0.0.1",
        remote_port=443,
        protocol="tcp",
    )
    assert conn.remote_addr == "10.0.0.1"


def test_network_info():
    conn = NetworkConnection(local_addr="0.0.0.0", local_port=80, remote_addr="1.2.3.4", remote_port=80)
    net = NetworkInfo(connections=(conn,))
    assert len(net.connections) == 1


# ---------- Генерация ID ----------

def test_generate_incident_id():
    id1 = generate_incident_id()
    id2 = generate_incident_id()
    assert id1 != id2
    assert id1.startswith("INC-")

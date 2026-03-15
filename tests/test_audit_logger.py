"""Тесты аудит-логирования (logging/audit.py)."""

import json
from pathlib import Path
from unittest.mock import patch

from phantom.core.state import (
    Context, Decision, Event, EventType, ResponseAction, ResponseResult, Severity,
)
from phantom.logging.audit import AuditLogger


def _event(**kwargs) -> Event:
    defaults = {
        "event_type": EventType.FILE_ACCESS,
        "target_path": "/opt/traps/ssh_key",
        "process_pid": 999,
        "source_sensor": "ebpf",
        "severity": Severity.HIGH,
    }
    defaults.update(kwargs)
    return Event(**defaults)


def _context(**kwargs) -> Context:
    return Context(event=_event(), threat_score=0.8, **kwargs)


def _decision(**kwargs) -> Decision:
    return Decision.from_context(
        context=_context(),
        actions=(ResponseAction.ALERT,),
        rationale="test decision",
        **kwargs,
    )


def _result(**kwargs) -> ResponseResult:
    return ResponseResult(
        decision_id="test-dec-id",
        action=ResponseAction.ALERT,
        success=True,
        message="alert_sent",
        **kwargs,
    )


# ---------- AuditLogger ----------

def test_audit_logger_creates_file(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("test_audit.jsonl")
    al.log(event=_event())
    assert (tmp_path / "test_audit.jsonl").exists()


def test_audit_log_event_only(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(event=_event())
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert "event" in entry
    assert entry["event"]["event_type"] == "file_access"


def test_audit_log_decision_only(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(decision=_decision())
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert "decision" in entry
    assert entry["decision"]["rationale"] == "test decision"


def test_audit_log_result_only(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(result=_result())
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert "result" in entry
    assert entry["result"]["success"] is True


def test_audit_log_context(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    ctx = _context()
    al.log(context=ctx)
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert "context" in entry
    assert entry["context"]["threat_score"] == 0.8


def test_audit_log_extra(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(extra={"custom_field": "value123"})
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert entry["extra"]["custom_field"] == "value123"


def test_audit_log_combined(tmp_path: Path):
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(event=_event(), decision=_decision(), result=_result())
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert "event" in entry
    assert "decision" in entry
    assert "result" in entry


def test_audit_log_empty_call(tmp_path: Path):
    """Вызов без аргументов записывает пустой объект."""
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log()
    line = (tmp_path / "audit.jsonl").read_text().strip()
    entry = json.loads(line)
    assert entry == {}


def test_audit_log_jsonl_format(tmp_path: Path):
    """Каждая запись на отдельной строке (JSONL)."""
    with patch("phantom.logging.audit.get_path", return_value=str(tmp_path)):
        al = AuditLogger("audit.jsonl")
    al.log(extra={"line": 1})
    al.log(extra={"line": 2})
    al.log(extra={"line": 3})
    lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    assert len(lines) == 3
    for i, line in enumerate(lines, 1):
        entry = json.loads(line)
        assert entry["extra"]["line"] == i

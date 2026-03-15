"""Тесты ECS-форматирования логов (logging/ecs.py)."""

import json
import logging

from phantom.logging.ecs import ecs_dict_from_record, ECSFormatter


def _make_record(msg: str = "test message", level: int = logging.INFO,
                 name: str = "phantom.test") -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=level,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


# ---------- ecs_dict_from_record ----------

def test_ecs_dict_has_required_fields():
    record = _make_record()
    ecs = ecs_dict_from_record(record)
    assert "@timestamp" in ecs
    assert "log.level" in ecs
    assert "log.logger" in ecs
    assert "message" in ecs
    assert "host" in ecs
    assert "event" in ecs


def test_ecs_dict_level_lowercase():
    record = _make_record(level=logging.WARNING)
    ecs = ecs_dict_from_record(record)
    assert ecs["log.level"] == "warning"


def test_ecs_dict_logger_name():
    record = _make_record(name="phantom.sensors")
    ecs = ecs_dict_from_record(record)
    assert ecs["log.logger"] == "phantom.sensors"


def test_ecs_dict_message():
    record = _make_record(msg="trap accessed by PID 1234")
    ecs = ecs_dict_from_record(record)
    assert ecs["message"] == "trap accessed by PID 1234"


def test_ecs_dict_timestamp_iso():
    record = _make_record()
    ecs = ecs_dict_from_record(record)
    ts = ecs["@timestamp"]
    assert "T" in ts  # ISO format
    assert "+" in ts or "Z" in ts or ts.endswith("+00:00")  # timezone aware


def test_ecs_dict_hostname():
    record = _make_record()
    ecs = ecs_dict_from_record(record)
    assert isinstance(ecs["host"]["hostname"], str)
    assert len(ecs["host"]["hostname"]) > 0


def test_ecs_dict_severity_number():
    record = _make_record(level=logging.ERROR)
    ecs = ecs_dict_from_record(record)
    assert ecs["event"]["severity"] == logging.ERROR


# ---------- ECSFormatter ----------

def test_formatter_returns_json():
    fmt = ECSFormatter()
    record = _make_record()
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["message"] == "test message"
    assert parsed["log.level"] == "info"


def test_formatter_with_exception():
    fmt = ECSFormatter()
    try:
        raise ValueError("test error")
    except ValueError:
        import sys
        record = _make_record(msg="exception occurred", level=logging.ERROR)
        record.exc_info = sys.exc_info()
    output = fmt.format(record)
    parsed = json.loads(output)
    assert "error" in parsed
    assert "ValueError" in parsed["error"]["message"]
    assert "test error" in parsed["error"]["message"]


def test_formatter_no_exception():
    fmt = ECSFormatter()
    record = _make_record()
    output = fmt.format(record)
    parsed = json.loads(output)
    assert "error" not in parsed


def test_formatter_unicode():
    fmt = ECSFormatter()
    record = _make_record(msg="Доступ к ловушке заблокирован")
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["message"] == "Доступ к ловушке заблокирован"


def test_formatter_all_levels():
    fmt = ECSFormatter()
    for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
        record = _make_record(level=level)
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["log.level"] == logging.getLevelName(level).lower()

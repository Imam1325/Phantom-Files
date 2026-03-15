"""Тесты ControlPlane."""

import asyncio
from datetime import datetime, timezone

import pytest
import yaml

from phantom.core.state import (
    Context, Decision, Event, EventType, ResponseAction, RunMode, Severity,
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


def _decision() -> Decision:
    ctx = Context(event=_event(), threat_score=1.0, incident_id="INC-test-001")
    return Decision.from_context(
        context=ctx,
        actions=(ResponseAction.ALERT,),
        rationale="test",
        auto_execute=True,
        action_params={},
        mode=RunMode.ACTIVE,
    )


def _make_control(tmp_path):
    """Создаёт ControlPlane с тестовыми путями."""
    import os
    # Подготовка минимального конфига
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    policies_path = config_dir / "policies.yaml"
    policies_path.write_text(yaml.safe_dump({"default": {"actions": ["alert"]}}))
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir(exist_ok=True)
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(exist_ok=True)
    traps_dir = tmp_path / "traps"
    traps_dir.mkdir(exist_ok=True)

    os.environ["PHANTOM_CONFIG_PATH"] = str(config_dir / "phantom.yaml")
    cfg_data = {
        "paths": {
            "policies": str(policies_path),
            "user_templates_dir": str(templates_dir),
            "logs_dir": str(logs_dir),
            "traps_dir": str(traps_dir),
        },
        "orchestrator": {"mode": "active"},
        "sensors": {},
    }
    cfg_path = config_dir / "phantom.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_data))
    os.chmod(cfg_path, 0o600)

    from phantom.core.config import clear_cache
    clear_cache()

    from phantom.core.control_plane import ControlPlane
    loop = asyncio.new_event_loop()
    cp = ControlPlane(loop)
    return cp, loop, policies_path


def test_on_decision(tmp_path):
    cp, loop, _ = _make_control(tmp_path)

    async def _run():
        decision = _decision()
        await cp.on_decision(decision)
        incidents = cp.list_incidents()
        assert len(incidents) == 1
        assert incidents[0]["incident_id"] == "INC-test-001"

    loop.run_until_complete(_run())
    loop.close()


def test_list_incidents_empty(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    assert cp.list_incidents() == []
    loop.close()


def test_get_incident_not_found(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    assert cp.get_incident("nonexistent") is None
    loop.close()


def test_get_policies(tmp_path):
    cp, loop, policies_path = _make_control(tmp_path)
    policies = cp.get_policies()
    assert "default" in policies
    loop.close()


def test_update_policies_requires_admin(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    with pytest.raises(PermissionError):
        cp.update_policies({"key": "val"}, role="viewer", replace=False)
    loop.close()


def test_update_policies_admin(tmp_path):
    cp, loop, policies_path = _make_control(tmp_path)
    result = cp.update_policies({"new_key": "new_val"}, role="admin", replace=False)
    assert "new_key" in result
    # Проверяем файл на диске
    data = yaml.safe_load(policies_path.read_text())
    assert data["new_key"] == "new_val"
    loop.close()


def test_update_policies_replace(tmp_path):
    cp, loop, policies_path = _make_control(tmp_path)
    result = cp.update_policies({"only_this": True}, role="admin", replace=True)
    assert result == {"only_this": True}
    # Старые ключи должны исчезнуть
    data = yaml.safe_load(policies_path.read_text())
    assert "default" not in data
    loop.close()


def test_policy_cooldown(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    # Первое изменение проходит
    cp.update_policies({"a": 1}, role="admin", replace=False)
    # Второе изменение блокируется кулдауном
    with pytest.raises(ValueError, match="Policy change cooldown"):
        cp.update_policies({"b": 2}, role="admin", replace=False)
    loop.close()


def test_create_block_invalid_kind(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    with pytest.raises(ValueError, match="kind"):
        cp.create_block({"kind": "invalid", "targets": ["1.2.3.4"]}, role="admin")
    loop.close()


def test_create_block_empty_targets(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    with pytest.raises(ValueError, match="targets"):
        cp.create_block({"kind": "ip", "targets": []}, role="admin")
    loop.close()


def test_mutate_templates_requires_role(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    with pytest.raises(PermissionError):
        cp.mutate_templates({"action": "add", "source": "x", "name": "y", "version": "v1.0.0"}, role="viewer")
    loop.close()


def test_mutate_templates_invalid_action(tmp_path):
    cp, loop, _ = _make_control(tmp_path)
    with pytest.raises(ValueError, match="Unsupported"):
        cp.mutate_templates({"action": "delete"}, role="admin")
    loop.close()


def test_incident_dedup_on_decision(tmp_path):
    """Повторный on_decision с тем же incident_id обновляет, а не дублирует."""
    cp, loop, _ = _make_control(tmp_path)

    async def _run():
        d1 = _decision()
        await cp.on_decision(d1)
        await cp.on_decision(d1)
        incidents = cp.list_incidents()
        assert len(incidents) == 1

    loop.run_until_complete(_run())
    loop.close()

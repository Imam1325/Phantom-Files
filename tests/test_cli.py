"""Тесты CLI (phantomctl)."""

import os

import pytest
import yaml

from phantom import cli as cli_module
from phantom.core.config import clear_cache


@pytest.fixture(autouse=True)
def _clean():
    clear_cache()
    old = os.environ.get("PHANTOM_CONFIG_PATH")
    yield
    clear_cache()
    if old is not None:
        os.environ["PHANTOM_CONFIG_PATH"] = old
    elif "PHANTOM_CONFIG_PATH" in os.environ:
        del os.environ["PHANTOM_CONFIG_PATH"]


def _setup_config(tmp_path, data=None) -> str:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(exist_ok=True)
    traps_dir = tmp_path / "traps"
    traps_dir.mkdir(exist_ok=True)
    cfg = data or {
        "orchestrator": {"mode": "active"},
        "sensors": {},
        "paths": {
            "policies": str(tmp_path / "policies.yaml"),
            "logs_dir": str(logs_dir),
            "traps_dir": str(traps_dir),
        },
    }
    # Убеждаемся что paths содержит необходимые ключи
    if "paths" in cfg:
        cfg["paths"].setdefault("logs_dir", str(logs_dir))
        cfg["paths"].setdefault("traps_dir", str(traps_dir))
    path = tmp_path / "phantom.yaml"
    path.write_text(yaml.safe_dump(cfg))
    os.chmod(path, 0o600)
    (tmp_path / "policies.yaml").write_text(yaml.safe_dump({}))
    return str(path)


def test_validate_valid_config(tmp_path):
    from phantom.cli import main
    cfg_path = _setup_config(tmp_path)
    rc = main(["--config", cfg_path, "validate"])
    assert rc == 0


def test_validate_invalid_config():
    from phantom.cli import main
    rc = main(["--config", "/nonexistent/phantom.yaml", "validate"])
    assert rc == 1


def test_mode_get(tmp_path):
    from phantom.cli import main
    cfg_path = _setup_config(tmp_path)
    rc = main(["--config", cfg_path, "mode", "get"])
    assert rc == 0


def test_mode_set_requires_root(tmp_path):
    """mode set требует root (euid == 0). На обычном пользователе вернёт 1."""
    from phantom.cli import main
    cfg_path = _setup_config(tmp_path)
    if os.geteuid() == 0:
        pytest.skip("Тест для непривилегированного пользователя")
    rc = main(["--config", cfg_path, "mode", "set", "observation"])
    assert rc == 1


def test_no_command_shows_help(tmp_path):
    from phantom.cli import main
    cfg_path = _setup_config(tmp_path)
    rc = main(["--config", cfg_path])
    assert rc == 0


def test_templates_list(tmp_path):
    from phantom.cli import main
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    cfg_path = _setup_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "sensors": {},
        "paths": {
            "user_templates_dir": str(templates_dir),
            "policies": str(tmp_path / "policies.yaml"),
        },
    })
    rc = main(["--config", cfg_path, "templates", "list"])
    assert rc == 0


def test_templates_add_activate_remove(tmp_path, monkeypatch):
    from phantom.cli import main

    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli_module.getpass, "getuser", lambda: "alice")
    monkeypatch.setattr(cli_module, "_groups_for_user", lambda _user: {"phantom-admin"})
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    source = tmp_path / "template.j2"
    source.write_text("hello {{ name }}", encoding="utf-8")
    cfg_path = _setup_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "sensors": {},
        "paths": {
            "user_templates_dir": str(templates_dir),
            "policies": str(tmp_path / "policies.yaml"),
        },
    })

    rc = main([
        "--config", cfg_path, "templates", "add",
        "--source", str(source), "--name", "demo", "--version", "v1.0.0",
    ])
    assert rc == 0

    rc = main([
        "--config", cfg_path, "templates", "activate",
        "--name", "demo", "--version", "v1.0.0",
    ])
    assert rc == 0

    rc = main([
        "--config", cfg_path, "templates", "show",
        "--name", "demo",
    ])
    assert rc == 0

    rc = main([
        "--config", cfg_path, "templates", "remove",
        "--name", "demo",
    ])
    assert rc == 0


def test_resolve_local_role_env(monkeypatch):
    monkeypatch.setenv("PHANTOM_ROLE", "editor")
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli_module.getpass, "getuser", lambda: "bob")
    monkeypatch.setattr(cli_module, "_groups_for_user", lambda _user: set())
    assert cli_module._resolve_local_role() == "viewer"


def test_resolve_local_role_sudo(monkeypatch):
    monkeypatch.delenv("PHANTOM_ROLE", raising=False)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli_module, "_groups_for_user", lambda _user: {"phantom-admin"})
    assert cli_module._resolve_local_role() == "admin"

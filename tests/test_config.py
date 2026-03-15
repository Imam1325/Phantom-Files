"""Тесты конфигурации (config.py)."""

import os
from pathlib import Path

import pytest
import yaml

from phantom.core.config import (
    get_config,
    clear_cache,
    ConfigError,
    _infer_type,
    _deep_merge,
    _deep_freeze,
)


@pytest.fixture(autouse=True)
def _clean_config_cache():
    """Очистка кеша конфигурации перед каждым тестом."""
    clear_cache()
    old_env = os.environ.get("PHANTOM_CONFIG_PATH")
    yield
    clear_cache()
    if old_env is not None:
        os.environ["PHANTOM_CONFIG_PATH"] = old_env
    elif "PHANTOM_CONFIG_PATH" in os.environ:
        del os.environ["PHANTOM_CONFIG_PATH"]


def _write_config(tmp_path, data: dict) -> Path:
    if "paths" in data:
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir(exist_ok=True)
        traps_dir = tmp_path / "traps"
        traps_dir.mkdir(exist_ok=True)
        data["paths"].setdefault("logs_dir", str(logs_dir))
        data["paths"].setdefault("traps_dir", str(traps_dir))
    p = tmp_path / "phantom.yaml"
    p.write_text(yaml.safe_dump(data))
    os.chmod(p, 0o600)
    return p


# ---------- get_config: базовые ----------

def test_get_config_minimal(tmp_path):
    cfg_path = _write_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "sensors": {},
        "paths": {},
    })
    cfg = get_config(str(cfg_path))
    assert cfg["orchestrator"]["mode"] == "active"


def test_get_config_with_env_override(tmp_path):
    cfg_path = _write_config(tmp_path, {
        "orchestrator": {"mode": "active", "worker_count": 4},
        "sensors": {},
        "paths": {},
    })
    os.environ["PHANTOM_ORCHESTRATOR__WORKER_COUNT"] = "8"
    try:
        cfg = get_config(str(cfg_path))
        assert cfg["orchestrator"]["worker_count"] == 8
    finally:
        del os.environ["PHANTOM_ORCHESTRATOR__WORKER_COUNT"]


def test_get_config_immutable(tmp_path):
    cfg_path = _write_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "paths": {},
    })
    cfg = get_config(str(cfg_path))
    with pytest.raises(TypeError):
        cfg["new_key"] = "value"


def test_get_config_reload(tmp_path):
    cfg_path = _write_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "paths": {},
    })
    cfg1 = get_config(str(cfg_path))
    assert cfg1["orchestrator"]["mode"] == "active"

    _write_config(tmp_path, {"orchestrator": {"mode": "observation"}, "paths": {}})
    cfg2 = get_config(str(cfg_path), reload=True)
    assert cfg2["orchestrator"]["mode"] == "observation"


def test_get_config_env_path(tmp_path):
    cfg_path = _write_config(tmp_path, {"orchestrator": {"mode": "dry_run"}, "paths": {}})
    os.environ["PHANTOM_CONFIG_PATH"] = str(cfg_path)
    cfg = get_config()
    assert cfg["orchestrator"]["mode"] == "dry_run"


def test_get_config_profiles(tmp_path):
    cfg_path = _write_config(tmp_path, {
        "orchestrator": {"mode": "active"},
        "paths": {},
        "profiles": {
            "prod": {"orchestrator": {"worker_count": 8}},
        },
    })
    cfg = get_config(str(cfg_path), profile="prod")
    assert cfg["orchestrator"]["mode"] == "active"


# ---------- get_config: ошибки ----------

def test_config_missing_file():
    with pytest.raises(ConfigError):
        get_config("/nonexistent/phantom.yaml")


def test_config_missing_required_paths(tmp_path):
    """Без секции paths — ConfigError."""
    p = tmp_path / "phantom.yaml"
    p.write_text(yaml.safe_dump({"orchestrator": {"mode": "active"}}))
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError, match="Missing required"):
        get_config(str(p))


def test_config_invalid_yaml(tmp_path):
    p = tmp_path / "phantom.yaml"
    p.write_text("{{{{invalid yaml::::")
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError, match="YAML"):
        get_config(str(p))


def test_config_not_a_dict(tmp_path):
    p = tmp_path / "phantom.yaml"
    p.write_text(yaml.safe_dump(["just", "a", "list"]))
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError, match="dictionary"):
        get_config(str(p))


def test_config_too_large(tmp_path):
    """Файл > 2MB — ConfigError."""
    p = tmp_path / "phantom.yaml"
    p.write_bytes(b"x" * (3 * 1024 * 1024))
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError, match="too large"):
        get_config(str(p))


def test_config_empty_path_value(tmp_path):
    """Пустое значение пути — ConfigError."""
    p = tmp_path / "phantom.yaml"
    p.write_text(yaml.safe_dump({
        "paths": {"logs_dir": "", "traps_dir": "/tmp/traps"},
    }))
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError, match="empty"):
        get_config(str(p))


# ---------- _infer_type ----------

def test_infer_type_bool():
    assert _infer_type("true") is True
    assert _infer_type("True") is True
    assert _infer_type("yes") is True
    assert _infer_type("on") is True
    assert _infer_type("false") is False
    assert _infer_type("False") is False
    assert _infer_type("no") is False
    assert _infer_type("off") is False


def test_infer_type_int():
    assert _infer_type("42") == 42
    assert _infer_type("0") == 0
    assert _infer_type("-1") == -1


def test_infer_type_float():
    assert _infer_type("3.14") == 3.14
    assert _infer_type("-0.5") == -0.5


def test_infer_type_string():
    assert _infer_type("hello") == "hello"
    assert _infer_type("/path/to/file") == "/path/to/file"


# ---------- _deep_merge ----------

def test_deep_merge_basic():
    base = {"a": 1, "b": {"c": 2}}
    override = {"b": {"d": 3}}
    result = _deep_merge(base, override)
    assert result == {"a": 1, "b": {"c": 2, "d": 3}}


def test_deep_merge_override_value():
    base = {"a": {"b": 1}}
    override = {"a": {"b": 2}}
    result = _deep_merge(base, override)
    assert result["a"]["b"] == 2


def test_deep_merge_new_key():
    base = {}
    override = {"x": "y"}
    result = _deep_merge(base, override)
    assert result == {"x": "y"}


def test_deep_merge_does_not_mutate_base():
    base = {"a": {"b": 1}}
    override = {"a": {"c": 2}}
    _deep_merge(base, override)
    assert "c" not in base["a"]


# ---------- _deep_freeze ----------

def test_deep_freeze_dict():
    frozen = _deep_freeze({"a": 1})
    with pytest.raises(TypeError):
        frozen["b"] = 2


def test_deep_freeze_nested():
    frozen = _deep_freeze({"a": {"b": [1, 2]}})
    assert frozen["a"]["b"] == (1, 2)
    with pytest.raises(TypeError):
        frozen["a"]["c"] = 3


def test_deep_freeze_list_to_tuple():
    frozen = _deep_freeze([1, 2, 3])
    assert frozen == (1, 2, 3)
    assert isinstance(frozen, tuple)


def test_deep_freeze_primitives():
    assert _deep_freeze(42) == 42
    assert _deep_freeze("str") == "str"
    assert _deep_freeze(None) is None


# ---------- кэширование ----------

def test_config_caches_result(tmp_path):
    cfg_path = _write_config(tmp_path, {"orchestrator": {"mode": "active"}, "paths": {}})
    cfg1 = get_config(str(cfg_path))
    cfg2 = get_config(str(cfg_path))
    assert cfg1 is cfg2


def test_clear_cache_forces_reload(tmp_path):
    cfg_path = _write_config(tmp_path, {"orchestrator": {"mode": "active"}, "paths": {}})
    cfg1 = get_config(str(cfg_path))
    clear_cache()
    cfg2 = get_config(str(cfg_path))
    assert cfg1 is not cfg2
    assert cfg2["orchestrator"]["mode"] == "active"

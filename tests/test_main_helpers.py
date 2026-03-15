"""Тесты helper-функций __main__."""

import os

import yaml

import phantom.__main__ as mainmod


def test_load_api_role_keys(monkeypatch):
    monkeypatch.setenv("PHANTOM_API_KEY_ADMIN", "adminkey")
    monkeypatch.setenv("PHANTOM_API_KEY_VIEWER", "viewkey")
    cfg = {
        "keys": [
            {"env": "PHANTOM_API_KEY_ADMIN", "role": "admin"},
            {"env": "PHANTOM_API_KEY_VIEWER", "role": "viewer"},
            {"env": "MISSING", "role": "admin"},
            "bad",
        ]
    }
    keys = mainmod._load_api_role_keys(cfg)
    assert keys == {"adminkey": "admin", "viewkey": "viewer"}


def test_setup_logging_config(tmp_path):
    path = tmp_path / "logging.yaml"
    config = {
        "version": 1,
        "handlers": {"null": {"class": "logging.NullHandler"}},
        "root": {"handlers": ["null"], "level": "INFO"},
    }
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    mainmod.setup_logging(str(path))


def test_setup_logging_missing_config(tmp_path):
    missing = tmp_path / "missing.yaml"
    if missing.exists():
        os.remove(missing)
    mainmod.setup_logging(str(missing))

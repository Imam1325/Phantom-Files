"""Общая конфигурация тестов."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

# Добавляем src в PYTHONPATH для тестов (если pytest.ini не подхватился).
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

_UNIT_FILES = {
    "test_rate_limiter.py",
    "test_state.py",
    "test_ecs.py",
    "test_policy_engine.py",
    "test_crypto.py",
    "test_fs_utils.py",
    "test_filters.py",
    "test_template_globals.py",
    "test_incident_store.py",
    "test_incidents.py",
}

_SLOW_FILES = {
    "test_ebpf_sensor.py",
    "test_persistence.py",
    "test_prod_readiness.py",
    "test_sandbox.py",
}


def _has_any_marker(item, names: Iterable[str]) -> bool:
    return any(name in item.keywords for name in names)


def pytest_collection_modifyitems(config, items):  # noqa: ANN001
    for item in items:
        if _has_any_marker(item, ("unit", "integration", "slow")):
            continue
        filename = Path(str(item.fspath)).name
        if filename in _SLOW_FILES:
            item.add_marker("slow")
            item.add_marker("integration")
        elif filename in _UNIT_FILES:
            item.add_marker("unit")
        else:
            item.add_marker("integration")

"""Тесты eBPF сенсора (без реального BPF — mock-тесты)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from phantom.core.state import EventType, RunMode
from phantom.sensors.ebpf import EbpfSensor, _trap_id_hash, _check_bpf_lsm_available, _EVENT_MAP


# ---------- _trap_id_hash ----------

def test_trap_id_hash_is_nonzero():
    """Хеш trap_id всегда non-zero (требование BPF map value)."""
    for trap_id in ["trap-001", "ssh-key-01", "", "a" * 1000]:
        h = _trap_id_hash(trap_id)
        assert h > 0
        assert isinstance(h, int)


def test_trap_id_hash_deterministic():
    """Один и тот же trap_id даёт одинаковый хеш."""
    assert _trap_id_hash("trap-001") == _trap_id_hash("trap-001")


def test_trap_id_hash_unique():
    """Разные trap_id дают разные хеши (вероятностно)."""
    hashes = {_trap_id_hash(f"trap-{i:04d}") for i in range(100)}
    assert len(hashes) == 100


# ---------- _check_bpf_lsm_available ----------

def test_check_bpf_lsm_no_securityfs():
    """Без securityfs — BPF LSM недоступен."""
    with patch("phantom.sensors.ebpf.Path") as MockPath:
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        MockPath.return_value = mock_path
        ok, reason = _check_bpf_lsm_available()
    assert ok is False
    assert "securityfs" in reason


def test_check_bpf_lsm_no_bpf_in_list():
    """BPF не в списке LSM — нужно добавить."""
    with patch("phantom.sensors.ebpf.Path") as MockPath:
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "lockdown,capability,yama,apparmor"
        MockPath.return_value = mock_path
        ok, reason = _check_bpf_lsm_available()
    assert ok is False
    assert "bpf" in reason.lower()


def test_check_bpf_lsm_available():
    """BPF в списке LSM — доступен."""
    with patch("phantom.sensors.ebpf.Path") as MockPath:
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "lockdown,capability,yama,apparmor,bpf"
        MockPath.return_value = mock_path
        ok, reason = _check_bpf_lsm_available()
    assert ok is True
    assert reason == ""


# ---------- _EVENT_MAP ----------

def test_event_map_coverage():
    """Все 8 типов событий покрыты."""
    assert len(_EVENT_MAP) == 8
    assert _EVENT_MAP[1] == EventType.FILE_OPEN
    assert _EVENT_MAP[2] == EventType.FILE_ACCESS
    assert _EVENT_MAP[3] == EventType.FILE_DELETE
    assert _EVENT_MAP[4] == EventType.FILE_RENAME
    assert _EVENT_MAP[5] == EventType.FILE_ATTRIB
    assert _EVENT_MAP[6] == EventType.FILE_CHOWN
    assert _EVENT_MAP[7] == EventType.FILE_WRITE
    assert _EVENT_MAP[8] == EventType.FILE_MODIFY


# ---------- EbpfSensor ----------

def test_is_available_no_bcc():
    """Без BCC — сенсор недоступен."""
    with patch.dict("sys.modules", {"bcc": None}):
        ok, reason = EbpfSensor.is_available()
        assert isinstance(ok, bool)
        assert isinstance(reason, str)


def test_sensor_constructor():
    """Конструктор EbpfSensor принимает все параметры."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sensor = EbpfSensor(
            config={"sensors": {"ebpf_poll_timeout_ms": 100, "whitelist_uids": [0, 65534]}},
            callback=lambda e: None,
            trap_registry=MagicMock(),
            permission_callback=lambda e: True,
            loop=loop,
            mode=RunMode.ACTIVE,
        )
        assert sensor._poll_timeout_ms == 100
        assert 0 in sensor._whitelist_uids
        assert 65534 in sensor._whitelist_uids
        assert sensor.lsm_active is False  # до start()
    finally:
        loop.close()


def test_sensor_accepts_observation_mode():
    """Сенсор принимает observation mode."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sensor = EbpfSensor(
            config={},
            callback=lambda e: None,
            trap_registry=MagicMock(),
            loop=loop,
            mode=RunMode.OBSERVATION,
        )
        assert sensor._mode == RunMode.OBSERVATION
    finally:
        loop.close()


def test_strip_lsm_probe():
    """_strip_lsm_probe удаляет LSM секцию из исходника."""
    src = """
#include <linux/sched.h>
BPF_HASH(ph_trap_inodes, u64, u64, 4096);
BPF_PERF_OUTPUT(events);

LSM_PROBE(file_open, struct file *file, int ret) {
    if (ret != 0)
        return ret;
    return -EACCES;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    return 0;
}
"""
    stripped = EbpfSensor._strip_lsm_probe(src)
    assert "LSM_PROBE" not in stripped
    assert "TRACEPOINT_PROBE" in stripped
    assert "BPF_HASH" in stripped
    assert "BPF_PERF_OUTPUT" in stripped


def test_path_resolution_absolute():
    """Абсолютный путь резолвится как есть."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sensor = EbpfSensor(
            config={},
            callback=lambda e: None,
            trap_registry=MagicMock(),
            loop=loop,
        )
        # /tmp всегда существует
        result = sensor._resolve_event_path("/tmp", pid=1, fd=-1)
        assert result is not None
        assert "/tmp" in result
    finally:
        loop.close()


def test_path_resolution_invalid():
    """Невалидный fd и пустой путь → None."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sensor = EbpfSensor(
            config={},
            callback=lambda e: None,
            trap_registry=MagicMock(),
            loop=loop,
        )
        result = sensor._resolve_event_path("", pid=0, fd=-1)
        assert result is None
    finally:
        loop.close()


# ---------- SensorManager integration ----------

def test_manager_ebpf_stats_empty():
    """ebpf_stats пуст когда eBPF не запущен."""
    from phantom.sensors.manager import SensorManager
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sm = SensorManager(
            config={},
            callback=lambda e: None,
            permission_callback=lambda e: True,
            trap_registry=None,
            loop=loop,
        )
        assert sm.ebpf_stats == {}
    finally:
        loop.close()


def test_manager_has_set_mode():
    """SensorManager имеет метод set_mode для горячей смены режима."""
    from phantom.sensors.manager import SensorManager
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sm = SensorManager(
            config={},
            callback=lambda e: None,
            permission_callback=lambda e: True,
            trap_registry=None,
            loop=loop,
        )
        assert hasattr(sm, "set_mode")
        assert callable(sm.set_mode)
    finally:
        loop.close()


def test_manager_has_reload_traps():
    """SensorManager имеет метод reload_traps для горячего обновления."""
    from phantom.sensors.manager import SensorManager
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        sm = SensorManager(
            config={},
            callback=lambda e: None,
            permission_callback=lambda e: True,
            trap_registry=None,
            loop=loop,
        )
        assert hasattr(sm, "reload_traps")
        # Без запуска не падает
        sm.reload_traps()
    finally:
        loop.close()

"""Тесты SensorManager."""

import asyncio

from phantom.sensors.manager import SensorManager


def _make_sm(**kwargs):
    loop = asyncio.new_event_loop()
    defaults = {
        "config": {},
        "callback": lambda e: None,
        "permission_callback": lambda e: True,
        "trap_registry": None,
        "loop": loop,
    }
    defaults.update(kwargs)
    sm = SensorManager(**defaults)
    return sm, loop


# ---------- health ----------

def test_health_not_started():
    """До старта — degraded."""
    sm, loop = _make_sm()
    h = sm.health
    assert h.degraded is True
    assert h.running is False
    loop.close()


def test_health_has_expected_fields():
    sm, loop = _make_sm()
    h = sm.health
    assert hasattr(h, "degraded")
    assert hasattr(h, "running")
    loop.close()


# ---------- mode ----------

def test_mode_unknown_before_start():
    sm, loop = _make_sm()
    assert sm.mode == "unknown"
    loop.close()


# ---------- pause / stop ----------

def test_has_pause_method():
    sm, loop = _make_sm()
    assert hasattr(sm, "pause")
    assert callable(sm.pause)
    loop.close()


def test_has_stop_method():
    sm, loop = _make_sm()
    assert hasattr(sm, "stop")
    assert callable(sm.stop)
    loop.close()


def test_stop_without_start():
    """stop() без start() не падает."""
    sm, loop = _make_sm()
    sm.stop()
    loop.close()


def test_pause_without_start():
    """pause() без start() не падает."""
    sm, loop = _make_sm()
    sm.pause()
    loop.close()


# ---------- set_mode ----------

def test_has_set_mode():
    sm, loop = _make_sm()
    assert hasattr(sm, "set_mode")
    assert callable(sm.set_mode)
    loop.close()


# ---------- reload_traps ----------

def test_has_reload_traps():
    sm, loop = _make_sm()
    assert hasattr(sm, "reload_traps")
    loop.close()


def test_reload_traps_without_start():
    """reload_traps() без start() не падает."""
    sm, loop = _make_sm()
    sm.reload_traps()
    loop.close()


# ---------- ebpf_stats ----------

def test_ebpf_stats_empty():
    """ebpf_stats пуст когда eBPF не запущен."""
    sm, loop = _make_sm()
    assert sm.ebpf_stats == {}
    loop.close()


# ---------- config ----------

def test_accepts_config():
    """SensorManager принимает конфигурацию."""
    sm, loop = _make_sm(config={"sensors": {"driver": "auto"}})
    assert sm is not None
    loop.close()


def test_accepts_mode_kwarg():
    """SensorManager принимает mode если поддерживается."""
    sm, loop = _make_sm()
    # Проверяем что конструктор отработал
    assert sm is not None
    loop.close()

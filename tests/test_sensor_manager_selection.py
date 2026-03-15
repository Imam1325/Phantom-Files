"""Тесты выбора сенсоров в SensorManager."""

import asyncio

from phantom.sensors import manager as sm
from phantom.core.state import RunMode


class _BaseSensor:
    def __init__(self, *args, **kwargs):  # noqa: ANN001
        self.started = False
        self.stopped = False
        self._mode = None

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    @property
    def health(self):
        from phantom.sensors.base import SensorHealth

        return SensorHealth(name="dummy", running=self.started, degraded=False, reason="")


class _DummyEbpf(_BaseSensor):
    lsm_active = True
    stats = {}

    @staticmethod
    def is_lsm_available():
        return True, ""

    def set_mode(self, mode):  # noqa: ANN001
        self._mode = mode

    def reload_traps(self):
        self._reloaded = True


class _DummyFanotify(_BaseSensor):
    pass


class _DummyInotify(_BaseSensor):
    pass


class _FailFanotify(_BaseSensor):
    def start(self):
        raise RuntimeError("fanotify unavailable")


def test_sensor_manager_auto_prefers_ebpf_lsm(monkeypatch):
    monkeypatch.setattr(sm, "EbpfSensor", _DummyEbpf)
    monkeypatch.setattr(sm, "FanotifySensor", _DummyFanotify)
    monkeypatch.setattr(sm, "InotifySensor", _DummyInotify)

    loop = asyncio.new_event_loop()
    mgr = sm.SensorManager(
        {"sensors": {"driver": "auto", "ebpf_enabled": True}},
        callback=lambda e: None,
        permission_callback=lambda e: True,
        trap_registry=None,
        loop=loop,
    )
    mgr.start()
    assert mgr.mode == "ebpf_lsm+fanotify"
    assert isinstance(mgr._sensor, _DummyEbpf)
    assert len(mgr._aux_sensors) == 1
    loop.close()


def test_sensor_manager_fallback_to_inotify(monkeypatch):
    monkeypatch.setattr(sm, "EbpfSensor", _DummyEbpf)
    monkeypatch.setattr(sm, "FanotifySensor", _FailFanotify)
    monkeypatch.setattr(sm, "InotifySensor", _DummyInotify)

    loop = asyncio.new_event_loop()
    mgr = sm.SensorManager(
        {"sensors": {"driver": "auto", "ebpf_enabled": False}},
        callback=lambda e: None,
        permission_callback=lambda e: True,
        trap_registry=None,
        loop=loop,
    )
    mgr.start()
    assert mgr.mode == "inotify_degraded"
    assert mgr.health.degraded is True
    loop.close()


def test_sensor_manager_forced_inotify(monkeypatch):
    monkeypatch.setattr(sm, "EbpfSensor", _DummyEbpf)
    monkeypatch.setattr(sm, "FanotifySensor", _DummyFanotify)
    monkeypatch.setattr(sm, "InotifySensor", _DummyInotify)

    loop = asyncio.new_event_loop()
    mgr = sm.SensorManager(
        {"sensors": {"driver": "inotify", "ebpf_enabled": True}},
        callback=lambda e: None,
        permission_callback=lambda e: True,
        trap_registry=None,
        loop=loop,
    )
    mgr.start()
    assert mgr.mode == "inotify_degraded"
    assert isinstance(mgr._sensor, _DummyInotify)
    assert mgr.health.degraded is True
    loop.close()


def test_sensor_manager_set_mode_and_reload(monkeypatch):
    monkeypatch.setattr(sm, "EbpfSensor", _DummyEbpf)
    monkeypatch.setattr(sm, "FanotifySensor", _DummyFanotify)
    monkeypatch.setattr(sm, "InotifySensor", _DummyInotify)

    loop = asyncio.new_event_loop()
    mgr = sm.SensorManager(
        {"sensors": {"driver": "auto", "ebpf_enabled": True}},
        callback=lambda e: None,
        permission_callback=lambda e: True,
        trap_registry=None,
        loop=loop,
    )
    mgr.start()
    mgr.set_mode(RunMode.OBSERVATION)
    mgr.reload_traps()
    assert isinstance(mgr._ebpf_sensor, _DummyEbpf)
    assert mgr._ebpf_sensor._mode == RunMode.OBSERVATION
    assert getattr(mgr._ebpf_sensor, "_reloaded", False) is True
    loop.close()

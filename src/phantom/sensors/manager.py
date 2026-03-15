"""
Менеджер сенсоров — иерархия режимов работы.

Приоритет сенсоров:
  1. eBPF LSM + fanotify  = FULL mode (blocking in kernel + PERM events)
  2. eBPF LSM only        = FULL mode (blocking in kernel via LSM)
  3. fanotify only        = STANDARD mode (PERM events, no kernel-level blocking)
  4. eBPF tracepoints     = DEGRADED (advisory only, no blocking)
  5. inotify              = DEGRADED (advisory only, no blocking)

eBPF LSM — killer-фича: блокировка в ядре через BPF-программу
на хуке security_file_open, с O(1) inode lookup.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Mapping, Optional

from phantom.core.state import RunMode
from phantom.core.traps import TrapRegistry
from phantom.sensors.base import EventCallback, PermissionCallback, Sensor, SensorHealth
from phantom.sensors.ebpf import EbpfSensor
from phantom.sensors.fanotify import FanotifySensor
from phantom.sensors.inotify import InotifySensor

logger = logging.getLogger("phantom.sensor.manager")


class SensorManager:
    def __init__(
        self,
        config: Mapping[str, Any],
        callback: EventCallback,
        permission_callback: PermissionCallback,
        trap_registry: TrapRegistry,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        mode: RunMode = RunMode.ACTIVE,
    ) -> None:
        self._config = config
        self._callback = callback
        self._permission_callback = permission_callback
        self._registry = trap_registry
        if loop is not None:
            self._loop = loop
        else:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError as exc:
                raise RuntimeError("SensorManager requires a running event loop") from exc
        self._mode = mode
        self._sensor: Sensor | None = None
        self._aux_sensors: list[Sensor] = []
        self._ebpf_sensor: EbpfSensor | None = None
        self._mode_name = "unknown"
        self._degraded = False
        self._degraded_reason = ""

    @property
    def health(self) -> SensorHealth:
        if self._sensor is None:
            return SensorHealth(name="none", running=False, degraded=True, reason="not started")
        primary = self._sensor.health
        aux_health = [sensor.health for sensor in self._aux_sensors]
        degraded = self._degraded or primary.degraded or any(item.degraded for item in aux_health)
        running = primary.running and all(item.running for item in aux_health if not item.degraded)
        reason_parts: list[str] = []
        if self._degraded_reason:
            reason_parts.append(self._degraded_reason)
        if primary.reason:
            reason_parts.append(f"primary:{primary.reason}")
        for item in aux_health:
            if item.reason:
                reason_parts.append(f"{item.name}:{item.reason}")
        return SensorHealth(
            name=self._mode_name,
            running=running,
            degraded=degraded,
            reason="; ".join(dict.fromkeys(reason_parts)),
        )

    @property
    def mode(self) -> str:
        return self._mode_name

    @property
    def ebpf_stats(self) -> dict[str, int]:
        """Статистика eBPF сенсора (если активен)."""
        if self._ebpf_sensor is not None:
            return self._ebpf_sensor.stats
        return {}

    def start(self) -> None:
        sensors_cfg = self._config.get("sensors", {}) if hasattr(self._config, "get") else {}
        prefer = str(sensors_cfg.get("driver", "auto")).lower()
        ebpf_enabled = bool(sensors_cfg.get("ebpf_enabled", True))
        self._degraded = False
        self._degraded_reason = ""
        self._aux_sensors = []
        self._ebpf_sensor = None

        if prefer == "auto":
            self._start_auto(sensors_cfg, ebpf_enabled)
        elif prefer == "ebpf":
            self._start_ebpf_primary(sensors_cfg)
        elif prefer == "fanotify":
            self._start_fanotify_primary(sensors_cfg, ebpf_enabled)
        elif prefer == "inotify":
            self._start_inotify_fallback()
        else:
            self._start_auto(sensors_cfg, ebpf_enabled)

    def _start_auto(self, sensors_cfg: Mapping[str, Any], ebpf_enabled: bool) -> None:
        """
        Автоматический выбор лучшей конфигурации.

        Приоритет:
          1. eBPF LSM (primary) + fanotify (auxiliary) → FULL
          2. eBPF LSM (primary) → FULL
          3. fanotify (primary) + eBPF tracepoints (auxiliary) → STANDARD
          4. fanotify (primary) → STANDARD
          5. eBPF tracepoints (primary) → DEGRADED
          6. inotify (fallback) → DEGRADED
        """
        ebpf_started = False
        fanotify_started = False

        # Попытка 1: eBPF LSM как primary
        if ebpf_enabled:
            lsm_ok, lsm_reason = EbpfSensor.is_lsm_available()
            if lsm_ok:
                try:
                    ebpf = EbpfSensor(
                        self._config, self._callback, self._registry,
                        permission_callback=self._permission_callback,
                        loop=self._loop, mode=self._mode,
                    )
                    ebpf.start()
                    if ebpf.lsm_active:
                        self._sensor = ebpf
                        self._ebpf_sensor = ebpf
                        ebpf_started = True
                        logger.info("Primary sensor: eBPF LSM (kernel-level blocking active)")
                    else:
                        ebpf.stop()
                except Exception as exc:
                    logger.warning("eBPF LSM start failed: %s", exc)
            else:
                logger.info("BPF LSM not available: %s", lsm_reason)

        # Попытка 2: fanotify
        try:
            fanotify = FanotifySensor(
                self._config,
                self._callback,
                self._registry,
                permission_callback=self._permission_callback,
                loop=self._loop,
            )
            fanotify.start()
            fanotify_started = True

            if ebpf_started:
                # eBPF LSM (primary) + fanotify (auxiliary) = FULL mode
                self._aux_sensors.append(fanotify)
                self._mode_name = "ebpf_lsm+fanotify"
                logger.info("Auxiliary sensor: fanotify (PERM events)")
            else:
                # fanotify (primary)
                self._sensor = fanotify
                logger.info("Primary sensor: fanotify")

        except Exception as exc:
            logger.warning("Fanotify unavailable: %s", exc)
            if not ebpf_started:
                self._degraded = True
                self._degraded_reason = f"fanotify_unavailable:{exc}"

        # Попытка 3: eBPF tracepoints (если eBPF LSM не запустился)
        if ebpf_enabled and not ebpf_started:
            try:
                ebpf = EbpfSensor(
                    self._config, self._callback, self._registry,
                    loop=self._loop, mode=self._mode,
                )
                ebpf.start()
                self._ebpf_sensor = ebpf

                if fanotify_started:
                    # fanotify (primary) + eBPF tracepoints (auxiliary)
                    self._aux_sensors.append(ebpf)
                    self._mode_name = "fanotify+ebpf"
                    logger.info("Auxiliary sensor: eBPF tracepoints")
                else:
                    # eBPF tracepoints only (degraded)
                    self._sensor = ebpf
                    self._mode_name = "ebpf_degraded"
                    self._degraded = True
                    self._degraded_reason = "ebpf_tracepoints_only_no_blocking"
                    logger.warning("Primary sensor: eBPF tracepoints only (degraded, no blocking)")
                    return

            except Exception as exc:
                logger.warning("eBPF tracepoints unavailable: %s", exc)
                self._degraded = True
                if self._degraded_reason:
                    self._degraded_reason += f";ebpf_unavailable:{exc}"
                else:
                    self._degraded_reason = f"ebpf_unavailable:{exc}"

        # Установка mode_name если ещё не установлен
        if ebpf_started and not fanotify_started:
            self._mode_name = "ebpf_lsm"
        elif fanotify_started and not ebpf_started and "ebpf" not in self._mode_name:
            self._mode_name = "fanotify"

        # Fallback: inotify
        if self._sensor is None:
            self._start_inotify_fallback()

    def _start_ebpf_primary(self, sensors_cfg: Mapping[str, Any]) -> None:
        """Принудительный запуск eBPF как primary."""
        try:
            ebpf = EbpfSensor(
                self._config, self._callback, self._registry,
                permission_callback=self._permission_callback,
                loop=self._loop, mode=self._mode,
            )
            ebpf.start()
            self._sensor = ebpf
            self._ebpf_sensor = ebpf

            if ebpf.lsm_active:
                self._mode_name = "ebpf_lsm"
                logger.info("Primary sensor: eBPF LSM (forced)")
            else:
                self._mode_name = "ebpf_degraded"
                self._degraded = True
                self._degraded_reason = "ebpf_tracepoints_only_no_blocking"
                logger.warning("Primary sensor: eBPF tracepoints only (LSM unavailable)")
        except Exception as exc:
            logger.critical("eBPF forced start failed: %s", exc)
            self._start_inotify_fallback()

    def _start_fanotify_primary(
        self, sensors_cfg: Mapping[str, Any], ebpf_enabled: bool,
    ) -> None:
        """Принудительный запуск fanotify как primary."""
        try:
            fanotify = FanotifySensor(
                self._config,
                self._callback,
                self._registry,
                permission_callback=self._permission_callback,
                loop=self._loop,
            )
            fanotify.start()
            self._sensor = fanotify
            self._mode_name = "fanotify"
            logger.info("Primary sensor: fanotify (forced)")

            if ebpf_enabled:
                self._start_ebpf_aux()

        except Exception as exc:
            logger.critical("Fanotify forced start failed: %s", exc)
            self._degraded = True
            self._degraded_reason = f"fanotify_unavailable:{exc}"
            self._start_inotify_fallback()

    def _start_ebpf_aux(self) -> None:
        """Запуск eBPF как вспомогательного сенсора."""
        try:
            ebpf = EbpfSensor(
                self._config, self._callback, self._registry,
                loop=self._loop, mode=self._mode,
            )
            ebpf.start()
            self._aux_sensors.append(ebpf)
            self._ebpf_sensor = ebpf

            if ebpf.lsm_active:
                self._mode_name = "fanotify+ebpf_lsm"
                logger.info("Auxiliary sensor: eBPF LSM")
            else:
                self._mode_name = "fanotify+ebpf"
                logger.info("Auxiliary sensor: eBPF tracepoints")

        except Exception as exc:
            logger.warning("eBPF auxiliary sensor unavailable: %s", exc)
            self._degraded = True
            if self._degraded_reason:
                self._degraded_reason += f";ebpf_unavailable:{exc}"
            else:
                self._degraded_reason = f"ebpf_unavailable:{exc}"

    def _start_inotify_fallback(self) -> None:
        """Inotify — последний запасной вариант."""
        try:
            inotify = InotifySensor(
                self._config, self._callback, self._registry, loop=self._loop,
            )
            inotify.start()
        except Exception as exc:
            self._sensor = None
            self._mode_name = "none"
            self._degraded = True
            self._degraded_reason = f"inotify_unavailable:{exc}"
            logger.error("Inotify fallback failed: %s", exc)
            return
        self._sensor = inotify
        self._mode_name = "inotify_degraded"
        self._degraded = True
        if not self._degraded_reason:
            self._degraded_reason = "inotify_fallback_no_blocking"
        logger.warning("Fallback sensor: inotify (degraded mode)")

    def set_mode(self, mode: RunMode) -> None:
        """Горячая смена режима блокировки."""
        self._mode = mode
        if self._ebpf_sensor is not None:
            self._ebpf_sensor.set_mode(mode)

    def reload_traps(self) -> None:
        """Горячее обновление таблицы ловушек в BPF map."""
        if self._ebpf_sensor is not None:
            self._ebpf_sensor.reload_traps()

    def pause(self) -> None:
        """Приостановка всех сенсоров (дренаж перед горячей перезагрузкой)."""
        for sensor in self._aux_sensors:
            try:
                if hasattr(sensor, "pause"):
                    sensor.pause()
                else:
                    sensor.stop()
            except Exception:
                pass
        if self._sensor is not None:
            try:
                if hasattr(self._sensor, "pause"):
                    self._sensor.pause()
                else:
                    self._sensor.stop()
            except Exception:
                pass

    def stop(self) -> None:
        for sensor in self._aux_sensors:
            try:
                sensor.stop()
            except Exception:
                pass
        self._aux_sensors = []
        if self._sensor is not None:
            self._sensor.stop()
        self._ebpf_sensor = None

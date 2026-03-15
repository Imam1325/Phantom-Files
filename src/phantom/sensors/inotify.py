"""
Резервный сенсор деградированного режима на базе watchdog/inotify.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Mapping, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
import platform

from watchdog.observers import Observer

from phantom.core.state import Event, EventType, Severity
from phantom.core.traps import TrapRegistry
from phantom.sensors.base import EventCallback, Sensor
from phantom.sensors.filters import DebounceFilter, path_match, resolve_pid_for_path

logger = logging.getLogger("phantom.sensor.inotify")

EVENT_MAP = {
    "opened": EventType.FILE_OPEN,
    "closed": EventType.FILE_ACCESS,
    "created": EventType.FILE_OPEN,
    "modified": EventType.FILE_MODIFY,
    "deleted": EventType.FILE_DELETE,
    "moved": EventType.FILE_RENAME,
}


class _WatchdogHandler(FileSystemEventHandler):
    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        callback: EventCallback,
        debounce: DebounceFilter,
        trap_registry: TrapRegistry,
        ignore_paths: list[str],
        whitelist_process_names: set[str],
        resolve_pid: bool,
        pid_lookup_timeout: float,
        pid_lookup_min_interval: float,
    ) -> None:
        super().__init__()
        self._loop = loop
        self._callback = callback
        self._debounce = debounce
        self._registry = trap_registry
        self._ignore_paths = ignore_paths
        self._whitelist_process_names = whitelist_process_names
        self._resolve_pid = resolve_pid
        self._pid_lookup_timeout = pid_lookup_timeout
        self._pid_lookup_min_interval = pid_lookup_min_interval

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        path = str(Path(event.src_path).resolve())
        if path_match(path, self._ignore_paths):
            return

        trap = self._registry.lookup(path)
        if trap is None:
            return

        key = f"{event.event_type}:{path}"
        if not self._debounce.allow(key):
            return

        pid = None
        proc_name = None
        if self._resolve_pid:
            pid, proc_name = resolve_pid_for_path(
                path,
                timeout_seconds=self._pid_lookup_timeout,
                min_interval_seconds=self._pid_lookup_min_interval,
            )
        if proc_name and proc_name in self._whitelist_process_names:
            event_type = EVENT_MAP.get(event.event_type, EventType.FILE_ACCESS)
            ev = Event(
                event_type=event_type,
                target_path=path,
                trap_id=trap.trap_id,
                source_sensor="inotify",
                process_pid=pid,
                process_name=proc_name,
                severity=Severity.INFO,
                raw_data={
                    "event": event.event_type,
                    "trap_category": trap.category,
                    "trap_priority": trap.priority,
                    "sensor_mode": "degraded",
                    "benign": True,
                },
            )
            asyncio.run_coroutine_threadsafe(self._callback(ev), self._loop)
            return

        event_type = EVENT_MAP.get(event.event_type, EventType.FILE_ACCESS)
        ev = Event(
            event_type=event_type,
            target_path=path,
            trap_id=trap.trap_id,
            source_sensor="inotify",
            process_pid=pid,
            process_name=proc_name,
            severity=Severity.CRITICAL,
            raw_data={
                "event": event.event_type,
                "trap_category": trap.category,
                "trap_priority": trap.priority,
                "sensor_mode": "degraded",
            },
        )
        asyncio.run_coroutine_threadsafe(self._callback(ev), self._loop)


class InotifySensor(Sensor):
    def __init__(
        self,
        config: Mapping[str, Any],
        callback: EventCallback,
        trap_registry: TrapRegistry,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        super().__init__(callback)
        if loop is not None:
            self._loop = loop
        else:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError as exc:
                raise RuntimeError("InotifySensor requires a running event loop") from exc
        if platform.system().lower() != "linux":
            raise RuntimeError("InotifySensor is supported only on Linux")
        self._observer = Observer()
        self._config = config
        self._registry = trap_registry
        self._debounce = DebounceFilter(window_seconds=1.0)

        sensors_cfg = config.get("sensors", {}) if hasattr(config, "get") else {}
        self._ignore_paths = list(sensors_cfg.get("ignore_paths", []))
        self._whitelist_process_names = {
            str(name).strip().lower() for name in sensors_cfg.get("whitelist_process_names", [])
        }
        self._resolve_pid = bool(sensors_cfg.get("inotify_pid_lookup", True))
        self._pid_lookup_timeout = float(sensors_cfg.get("inotify_pid_lookup_timeout", 0.3))
        self._pid_lookup_min_interval = float(sensors_cfg.get("inotify_pid_lookup_min_interval", 0.2))

    def start(self) -> None:
        traps_root = Path(self._registry.root)
        traps_root.mkdir(parents=True, exist_ok=True)

        handler = _WatchdogHandler(
            loop=self._loop,
            callback=self._callback,
            debounce=self._debounce,
            trap_registry=self._registry,
            ignore_paths=self._ignore_paths,
            whitelist_process_names=self._whitelist_process_names,
            resolve_pid=self._resolve_pid,
            pid_lookup_timeout=self._pid_lookup_timeout,
            pid_lookup_min_interval=self._pid_lookup_min_interval,
        )
        self._observer.schedule(handler, str(traps_root), recursive=True)
        self._observer.start()
        self._running = True
        self._degraded = True
        self._reason = "Fallback sensor active (inotify), pre-access deny unavailable"
        logger.warning("Inotify fallback sensor started for %s", traps_root)

    def stop(self) -> None:
        if not self._running:
            return
        self._observer.stop()
        self._observer.join()
        self._running = False
        logger.info("Inotify sensor stopped")

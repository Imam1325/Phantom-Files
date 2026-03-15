"""
Сенсор fanotify PERM (основной) с fail-close по таймауту -> запрет.
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
import logging
import os
import platform
import struct
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from phantom.core.state import Event, EventType, Severity
from phantom.core.traps import TrapRegistry
from phantom.sensors.base import EventCallback, PermissionCallback, Sensor

logger = logging.getLogger("phantom.sensor.fanotify")

# Константы fanotify
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020

FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_DONT_FOLLOW = 0x00000004
FAN_MARK_ONLYDIR = 0x00000008
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_IGNORED_MASK = 0x00000020
FAN_MARK_IGNORED_SURV_MODIFY = 0x00000040
FAN_MARK_FLUSH = 0x00000080
FAN_MARK_FILESYSTEM = 0x00000100

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_OPEN_EXEC = 0x00001000

FAN_OPEN_PERM = 0x00010000
FAN_ACCESS_PERM = 0x00020000
FAN_OPEN_EXEC_PERM = 0x00040000

FAN_EVENT_ON_CHILD = 0x08000000

FAN_ALLOW = 0x01
FAN_DENY = 0x02

FANOTIFY_METADATA_FMT = "IBBHQii"
FANOTIFY_METADATA_LEN = struct.calcsize(FANOTIFY_METADATA_FMT)
FANOTIFY_RESPONSE_FMT = "iI"

SYS_fanotify_init = {
    ("x86_64",): 300,
    ("amd64",): 300,
    ("aarch64",): 262,
    ("arm64",): 262,
}.get((platform.machine().lower(),), -1)
SYS_fanotify_mark = {
    ("x86_64",): 301,
    ("amd64",): 301,
    ("aarch64",): 263,
    ("arm64",): 263,
}.get((platform.machine().lower(),), -1)


def _event_type_from_mask(mask: int) -> EventType:
    if mask & FAN_OPEN_PERM:
        return EventType.FILE_OPEN
    if mask & FAN_ACCESS_PERM:
        return EventType.FILE_ACCESS
    if mask & FAN_DELETE:
        return EventType.FILE_DELETE
    if mask & FAN_MOVED_FROM or mask & FAN_MOVED_TO:
        return EventType.FILE_RENAME
    if mask & FAN_MODIFY:
        return EventType.FILE_MODIFY
    if mask & FAN_ATTRIB:
        return EventType.FILE_ATTRIB
    return EventType.FILE_ACCESS


def _process_name(pid: int) -> Optional[str]:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _process_uid(pid: int) -> Optional[int]:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
    return None


class FanotifySensor(Sensor):
    def __init__(
        self,
        config: Mapping[str, Any],
        callback: EventCallback,
        trap_registry: TrapRegistry,
        permission_callback: PermissionCallback,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        super().__init__(callback)
        self._config = config
        self._registry = trap_registry
        self._perm_cb = permission_callback
        self._loop = loop or asyncio.get_running_loop()
        self._fd: Optional[int] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        sensors_cfg = config.get("sensors", {}) if hasattr(config, "get") else {}
        self._permission_timeout_ms = int(sensors_cfg.get("permission_timeout_ms", 50))
        self._whitelist_process_names = {
            str(x).strip().lower() for x in sensors_cfg.get("whitelist_process_names", [])
        }

    @staticmethod
    def is_available() -> tuple[bool, str]:
        if os.name != "posix":
            return False, "non-posix platform"
        if SYS_fanotify_init <= 0 or SYS_fanotify_mark <= 0:
            return False, f"unsupported arch for fanotify syscall: {platform.machine()}"
        return True, ""

    def start(self) -> None:
        ok, reason = self.is_available()
        if not ok:
            self._degraded = True
            self._reason = reason
            raise RuntimeError(reason)

        self._fd = self._fanotify_init()
        self._apply_marks(self._fd)
        self._running = True
        self._degraded = False
        self._reason = ""

        self._stop.clear()
        self._thread = threading.Thread(target=self._reader_loop, daemon=True, name="phantom-fanotify")
        self._thread.start()
        logger.info("Fanotify sensor started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self._running = False
        logger.info("Fanotify sensor stopped")

    def _fanotify_init(self) -> int:
        flags = FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_PRE_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
        event_f_flags = os.O_RDONLY
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.syscall(SYS_fanotify_init, flags, event_f_flags)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"fanotify_init failed: {os.strerror(err)}")
        return int(fd)

    def _apply_marks(self, fan_fd: int) -> None:
        dirs = {str(Path(entry.output_path).resolve().parent) for entry in self._registry.entries()}
        mask = (
            FAN_OPEN_PERM
            | FAN_ACCESS_PERM
            | FAN_MODIFY
            | FAN_DELETE
            | FAN_MOVED_FROM
            | FAN_MOVED_TO
            | FAN_ATTRIB
            | FAN_EVENT_ON_CHILD
        )
        mark_flags = FAN_MARK_ADD
        libc = ctypes.CDLL(None, use_errno=True)
        for path in sorted(dirs):
            p = Path(path)
            if not p.exists():
                continue
            bpath = str(p).encode("utf-8")
            rc = libc.syscall(SYS_fanotify_mark, fan_fd, mark_flags, mask, -1, ctypes.c_char_p(bpath))
            if rc < 0:
                err = ctypes.get_errno()
                raise OSError(err, f"fanotify_mark failed for {path}: {os.strerror(err)}")

    def _reader_loop(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        while not self._stop.is_set():
            try:
                data = os.read(fd, 8192)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except InterruptedError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EBADF, errno.EINVAL):
                    break
                logger.error("fanotify read error: %s", exc)
                continue

            if not data:
                continue
            self._consume_buffer(data)

    def _consume_buffer(self, data: bytes) -> None:
        offset = 0
        while offset + FANOTIFY_METADATA_LEN <= len(data):
            chunk = data[offset : offset + FANOTIFY_METADATA_LEN]
            event_len, vers, _reserved, _metadata_len, mask, fd, pid = struct.unpack(
                FANOTIFY_METADATA_FMT, chunk
            )
            if event_len <= 0:
                break
            offset += event_len
            if fd < 0:
                continue
            self._handle_single_event(mask, fd, pid)

    def _handle_single_event(self, mask: int, event_fd: int, pid: int) -> None:
        path: Optional[str] = None
        is_perm_event = False
        try:
            path = str(Path(f"/proc/self/fd/{event_fd}").resolve())
            trap = self._registry.lookup(path)
            is_perm_event = bool(mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM))

            if trap is None:
                if is_perm_event:
                    self._send_permission_response(event_fd, True)
                return

            proc_name = (_process_name(pid) or "").strip()
            proc_uid = _process_uid(pid)
            if proc_name.lower() in self._whitelist_process_names:
                if is_perm_event:
                    self._send_permission_response(event_fd, True)
                event = Event(
                    event_type=_event_type_from_mask(mask),
                    target_path=path,
                    trap_id=trap.trap_id,
                    source_sensor="fanotify",
                    process_pid=pid,
                    process_name=proc_name,
                    process_uid=proc_uid,
                    severity=Severity.INFO,
                    raw_data={"mask": int(mask), "benign": True},
                )
                asyncio.run_coroutine_threadsafe(self._callback(event), self._loop)
                return

            event = Event(
                event_type=_event_type_from_mask(mask),
                target_path=path,
                trap_id=trap.trap_id,
                source_sensor="fanotify",
                process_pid=pid,
                process_name=proc_name or None,
                process_uid=proc_uid,
                severity=Severity.CRITICAL,
                raw_data={"mask": int(mask), "perm_event": is_perm_event},
            )

            allow = False
            if is_perm_event:
                timeout = max(1, self._permission_timeout_ms) / 1000.0
                allow = self._permission_decision(event, timeout_seconds=timeout)
                self._send_permission_response(event_fd, allow)

            # Всегда отправляем событие в конвейер аудита/реагирования.
            asyncio.run_coroutine_threadsafe(self._callback(event), self._loop)
        except Exception as exc:
            logger.error("fanotify event handler failed (pid=%s path=%s): %s", pid, path, exc)
            try:
                if is_perm_event:
                    self._send_permission_response(event_fd, False)
            except Exception:
                pass
        finally:
            try:
                os.close(event_fd)
            except OSError:
                pass

    def _permission_decision(self, event: Event, timeout_seconds: float) -> bool:
        try:
            future = asyncio.run_coroutine_threadsafe(self._perm_cb(event), self._loop)
            return bool(future.result(timeout=timeout_seconds))
        except Exception:
            # fail-close при таймауте или ошибках callback
            return False

    def _send_permission_response(self, event_fd: int, allow: bool) -> None:
        if self._fd is None:
            return
        response = FAN_ALLOW if allow else FAN_DENY
        payload = struct.pack(FANOTIFY_RESPONSE_FMT, int(event_fd), int(response))
        os.write(self._fd, payload)

"""
Основной сенсор Phantom на базе BPF LSM.

Killer-фича проекта: BPF-программа на хуке security_file_open блокирует
доступ к ловушкам ДО того, как файловый дескриптор будет создан.

Архитектура:
  ┌─────────────────────────────────────────────────────────┐
  │ KERNEL                                                  │
  │                                                         │
  │  LSM_PROBE(file_open)                                   │
  │    │                                                    │
  │    ├─ inode ∉ ph_trap_inodes → return 0 (allow, O(1))   │
  │    │                                                    │
  │    ├─ inode ∈ ph_trap_inodes:                            │
  │    │    ├─ uid ∈ ph_whitelist → return 0                 │
  │    │    ├─ submit event → perf buffer → userspace        │
  │    │    ├─ ph_block_mode[0]==1 → return -EACCES (BLOCK)  │
  │    │    └─ ph_block_mode[0]==0 → return 0 (observe)      │
  │    │                                                    │
  │  Tracepoints (openat, write, unlink, rename, ...)       │
  │    └─ submit_path_event → perf buffer → userspace        │
  └─────────────────────────────────────────────────────────┘

Преимущества перед fanotify:
  - Блокировка в ядре: нет context switch, < 1 μs для non-trap файлов.
  - O(1) inode-based фильтрация вместо path comparison.
  - Полный контекст процесса прямо из ядра (pid, uid, comm).
  - Не зависит от fanotify_init (не нужен CAP_SYS_ADMIN для fanotify).

Требования:
  - Kernel >= 5.7, CONFIG_BPF_LSM=y
  - "bpf" в lsm= (grub: lsm=lockdown,capability,landlock,yama,apparmor,bpf)
  - python3-bpfcc (BCC)
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import logging
import os
import struct
import threading
from pathlib import Path
from typing import Any, Mapping, Optional

from phantom.core.state import Event, EventType, RunMode, Severity
from phantom.core.traps import TrapRegistry
from phantom.sensors.base import EventCallback, PermissionCallback, Sensor

logger = logging.getLogger("phantom.sensor.ebpf")

_EVENT_MAP: dict[int, EventType] = {
    1: EventType.FILE_OPEN,
    2: EventType.FILE_ACCESS,
    3: EventType.FILE_DELETE,
    4: EventType.FILE_RENAME,
    5: EventType.FILE_ATTRIB,
    6: EventType.FILE_CHOWN,
    7: EventType.FILE_WRITE,
    8: EventType.FILE_MODIFY,
}


def _trap_id_hash(trap_id: str) -> int:
    """Генерация u64 хеша trap_id для BPF map value."""
    digest = hashlib.sha256(trap_id.encode()).digest()[:8]
    return struct.unpack("<Q", digest)[0] | 1  # гарантируем non-zero


def _check_bpf_lsm_available() -> tuple[bool, str]:
    """Проверка доступности BPF LSM на хосте."""
    lsm_path = Path("/sys/kernel/security/lsm")
    if not lsm_path.exists():
        return False, "securityfs not mounted (/sys/kernel/security/lsm missing)"
    try:
        lsm_list = lsm_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return False, f"cannot read LSM list: {exc}"
    if "bpf" not in lsm_list.split(","):
        return False, (
            f"BPF LSM not enabled. Current LSM: {lsm_list}. "
            f"Add 'bpf' to kernel cmdline: lsm={lsm_list},bpf"
        )
    return True, ""


class EbpfSensor(Sensor):
    """
    Основной BPF LSM сенсор с блокировкой доступа к ловушкам.

    Может работать в двух режимах:
      - LSM mode (полный): LSM_PROBE(file_open) + tracepoints.
        Блокирует доступ к ловушкам в ядре.
      - Tracepoint-only mode (деградированный): только tracepoints.
        Advisory monitoring без блокировки.
    """

    def __init__(
        self,
        config: Mapping[str, Any],
        callback: EventCallback,
        trap_registry: TrapRegistry,
        permission_callback: Optional[PermissionCallback] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        mode: RunMode = RunMode.ACTIVE,
    ) -> None:
        super().__init__(callback)
        self._config = config
        self._registry = trap_registry
        self._perm_cb = permission_callback
        self._loop = loop or asyncio.get_running_loop()
        self._mode = mode
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._mode_lock = threading.Lock()
        self._bpf: Any = None
        self._events: Any = None
        self._lsm_active = False

        sensors_cfg = config.get("sensors", {}) if hasattr(config, "get") else {}
        self._poll_timeout_ms = int(sensors_cfg.get("ebpf_poll_timeout_ms", 200))
        self._source_path = sensors_cfg.get("ebpf_program") or str(
            (Path(__file__).resolve().parent / "ebpf" / "fs_sensor.bpf.c")
        )
        self._whitelist_process_names = {
            str(x).strip().lower() for x in sensors_cfg.get("whitelist_process_names", [])
        }
        self._whitelist_uids: set[int] = set()
        # UID самого демона всегда в whitelist
        self._whitelist_uids.add(os.getuid())
        for uid_val in sensors_cfg.get("whitelist_uids", []):
            try:
                self._whitelist_uids.add(int(uid_val))
            except (TypeError, ValueError):
                pass

    @staticmethod
    def is_available() -> tuple[bool, str]:
        """Проверка наличия BCC."""
        try:
            import bcc  # type: ignore  # noqa: F401
        except Exception as exc:
            return False, f"bcc unavailable: {exc}"
        return True, ""

    @staticmethod
    def is_lsm_available() -> tuple[bool, str]:
        """Проверка доступности BPF LSM (kernel + config)."""
        ok, reason = EbpfSensor.is_available()
        if not ok:
            return ok, reason
        return _check_bpf_lsm_available()

    @property
    def lsm_active(self) -> bool:
        """True если LSM blocking активен (killer feature)."""
        return self._lsm_active

    @property
    def stats(self) -> dict[str, int]:
        """Статистика из BPF per-CPU counters."""
        if self._bpf is None:
            return {}
        try:
            stat_map = self._bpf["ph_stats"]
            labels = ["events_submitted", "accesses_blocked", "trap_hits", "trap_misses"]
            result = {}
            for i, label in enumerate(labels):
                total = 0
                for cpu_val in stat_map[ctypes.c_int(i)]:
                    total += cpu_val.value
                result[label] = total
            return result
        except Exception:
            return {}

    def start(self) -> None:
        ok, reason = self.is_available()
        if not ok:
            self._degraded = True
            self._reason = reason
            raise RuntimeError(reason)

        source = Path(self._source_path)
        if not source.exists():
            self._degraded = True
            self._reason = f"eBPF source not found: {source}"
            raise RuntimeError(self._reason)

        lsm_ok, lsm_reason = _check_bpf_lsm_available()

        src_text = source.read_text(encoding="utf-8")
        if not lsm_ok:
            # Деградированный режим: вырезаем LSM_PROBE из исходника
            logger.warning("BPF LSM unavailable: %s. Falling back to tracepoints only.", lsm_reason)
            src_text = self._strip_lsm_probe(src_text)

        try:
            from bcc import BPF  # type: ignore

            self._bpf = BPF(text=src_text)
            self._events = self._bpf["events"]
            self._events.open_perf_buffer(self._on_perf_event, page_cnt=64)

            if lsm_ok:
                self._lsm_active = True
                logger.info("BPF LSM probe attached to security_file_open")
            else:
                self._lsm_active = False

        except Exception as exc:
            self._degraded = True
            self._reason = f"eBPF init failed: {exc}"
            raise RuntimeError(self._reason) from exc

        # Заполняем BPF maps
        self._populate_trap_maps()
        self._populate_whitelist_map()
        self._set_block_mode(self._mode == RunMode.ACTIVE)

        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._reader_loop, daemon=True, name="phantom-ebpf"
        )
        self._thread.start()
        self._degraded = not self._lsm_active
        if self._degraded:
            self._reason = "tracepoint-only mode, no LSM blocking"
        else:
            self._reason = ""

        mode_label = "LSM+tracepoints" if self._lsm_active else "tracepoints-only (degraded)"
        logger.info(
            "eBPF sensor started: mode=%s, traps=%d, block=%s",
            mode_label,
            len(self._registry.entries()),
            self._mode == RunMode.ACTIVE and self._lsm_active,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._events = None
        self._bpf = None
        self._running = False
        self._lsm_active = False
        logger.info("eBPF sensor stopped")

    def set_mode(self, mode: RunMode) -> None:
        """Горячая смена режима блокировки (без перезагрузки BPF)."""
        with self._mode_lock:
            self._mode = mode
        block = mode == RunMode.ACTIVE and self._lsm_active
        self._set_block_mode(block)
        logger.info("eBPF block mode changed: mode=%s block=%s", mode.value, block)

    def reload_traps(self) -> None:
        """Горячее обновление таблицы ловушек в BPF map."""
        self._populate_trap_maps()
        logger.info("eBPF trap maps reloaded: %d traps", len(self._registry.entries()))

    # ---------- BPF map management ----------

    def _populate_trap_maps(self) -> None:
        """Заполнение ph_trap_inodes и ph_trap_devs из TrapRegistry."""
        if self._bpf is None:
            return

        trap_map = self._bpf["ph_trap_inodes"]
        dev_map = self._bpf["ph_trap_devs"]

        # Строим новые записи во временных словарях, чтобы избежать
        # окна без защиты между clear() и повторным заполнением.
        new_trap_entries: dict[int, int] = {}
        new_dev_entries: dict[int, int] = {}

        for entry in self._registry.entries():
            path = Path(entry.output_path)
            if not path.exists():
                logger.debug("Trap file not found (skip inode mapping): %s", path)
                continue
            try:
                stat = path.stat()
                new_trap_entries[stat.st_ino] = _trap_id_hash(entry.trap_id)
                new_dev_entries[stat.st_dev] = 1
            except OSError as exc:
                logger.warning("Cannot stat trap file %s: %s", path, exc)

        # Добавляем/обновляем новые записи
        for ino, trap_hash in new_trap_entries.items():
            trap_map[ctypes.c_uint64(ino)] = ctypes.c_uint64(trap_hash)
        for dev, val in new_dev_entries.items():
            dev_map[ctypes.c_uint64(dev)] = ctypes.c_uint64(val)

        # Удаляем устаревшие записи
        current_trap_keys = set(trap_map.keys())
        for key in current_trap_keys:
            if key.value not in new_trap_entries:
                del trap_map[key]
        current_dev_keys = set(dev_map.keys())
        for key in current_dev_keys:
            if key.value not in new_dev_entries:
                del dev_map[key]

        loaded = len(new_trap_entries)
        logger.info("Loaded %d/%d trap inodes into BPF map", loaded, len(self._registry.entries()))

    def _populate_whitelist_map(self) -> None:
        """Заполнение ph_whitelist из конфигурации."""
        if self._bpf is None:
            return
        wl_map = self._bpf["ph_whitelist"]
        for uid in self._whitelist_uids:
            wl_map[ctypes.c_uint32(uid)] = ctypes.c_uint32(1)
        logger.debug("Whitelisted %d UIDs in BPF map", len(self._whitelist_uids))

    def _set_block_mode(self, enabled: bool) -> None:
        """Установка флага блокировки в BPF map."""
        if self._bpf is None:
            return
        block_map = self._bpf["ph_block_mode"]
        block_map[ctypes.c_int(0)] = ctypes.c_uint64(1 if enabled else 0)

    # ---------- BPF program source manipulation ----------

    @staticmethod
    def _strip_lsm_probe(src: str) -> str:
        """Удаление LSM_PROBE секции из BPF исходника для tracepoint-only режима."""
        lines = src.split("\n")
        result: list[str] = []
        skip = False
        brace_depth = 0
        found_body = False
        for line in lines:
            if not skip and "LSM_PROBE(" in line:
                skip = True
                brace_depth = 0
                found_body = False
            if skip:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth > 0:
                    found_body = True
                if found_body and brace_depth <= 0:
                    skip = False
                continue
            result.append(line)
        return "\n".join(result)

    # ---------- perf buffer reader ----------

    def _reader_loop(self) -> None:
        if self._bpf is None:
            return
        while not self._stop.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=self._poll_timeout_ms)
            except Exception as exc:
                if self._stop.is_set():
                    break
                logger.error("eBPF perf poll failed: %s", exc)

    def _on_perf_event(self, cpu: int, data: int, size: int) -> None:
        if self._events is None:
            return
        try:
            raw = self._events.event(data)
            pid = int(getattr(raw, "tgid", 0))
            fd = int(getattr(raw, "fd", -1))
            flags = int(getattr(raw, "flags", 0))
            inode = int(getattr(raw, "inode", 0))
            dev = int(getattr(raw, "dev", 0))
            raw_path = bytes(raw.path).split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
            path = self._resolve_event_path(raw_path, pid=pid, fd=fd)
            if not path:
                return

            trap = self._registry.lookup(path)
            if trap is None:
                return

            proc_name = bytes(raw.comm).split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
            uid = int(getattr(raw, "uid", 0))
            event_type = _EVENT_MAP.get(int(raw.event_type), EventType.FILE_ACCESS)

            # Benign: whitelisted process name
            if proc_name.lower() in self._whitelist_process_names:
                event = Event(
                    event_type=event_type,
                    target_path=path,
                    trap_id=trap.trap_id,
                    source_sensor="ebpf",
                    process_pid=pid,
                    process_name=proc_name or None,
                    process_uid=uid,
                    severity=Severity.INFO,
                    raw_data={
                        "event_type": int(raw.event_type),
                        "benign": True,
                        "fd": fd,
                        "flags": flags,
                        "inode": inode,
                        "dev": dev,
                        "lsm_blocked": False,
                    },
                )
                asyncio.run_coroutine_threadsafe(self._callback(event), self._loop)
                return

            # LSM blocking уже произошёл в ядре — отмечаем в raw_data
            with self._mode_lock:
                current_mode = self._mode
            lsm_blocked = (
                self._lsm_active
                and current_mode == RunMode.ACTIVE
                and event_type == EventType.FILE_OPEN
            )

            event = Event(
                event_type=event_type,
                target_path=path,
                trap_id=trap.trap_id,
                source_sensor="ebpf",
                process_pid=pid,
                process_name=proc_name or None,
                process_uid=uid,
                severity=Severity.CRITICAL,
                raw_data={
                    "event_type": int(raw.event_type),
                    "cpu": int(cpu),
                    "size": int(size),
                    "fd": fd,
                    "flags": flags,
                    "inode": inode,
                    "dev": dev,
                    "lsm_blocked": lsm_blocked,
                },
            )
            asyncio.run_coroutine_threadsafe(self._callback(event), self._loop)
        except Exception as exc:
            logger.warning("eBPF event decode failed: %s", exc)

    # ---------- path resolution ----------

    def _resolve_event_path(self, raw_path: str, pid: int, fd: int) -> Optional[str]:
        if raw_path:
            candidate = Path(raw_path)
            if candidate.is_absolute():
                try:
                    return str(candidate.resolve())
                except Exception:
                    return None
            cwd = self._process_cwd(pid)
            if cwd:
                try:
                    return str((Path(cwd) / raw_path).resolve())
                except Exception:
                    return None
        return self._path_from_fd(pid, fd)

    def _process_cwd(self, pid: int) -> Optional[str]:
        if pid <= 0:
            return None
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except Exception:
            return None

    def _path_from_fd(self, pid: int, fd: int) -> Optional[str]:
        if pid <= 0 or fd < 0:
            return None
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
            if not target.startswith("/"):
                return None
            return str(Path(target).resolve())
        except Exception:
            return None

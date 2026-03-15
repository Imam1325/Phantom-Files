"""
Кольцевой буфер предзахвата пакетов через eBPF для сбора сетевых улик.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Mapping, Optional


def _memory_total_mb() -> Optional[int]:
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                kb = int(parts[1])
                return kb // 1024
    return None


def _resolve_default_iface() -> Optional[str]:
    try:
        for _idx, name in socket.if_nameindex():
            lowered = name.lower()
            if lowered.startswith("lo"):
                continue
            return name
    except Exception:
        return None
    return None


def _extract_ports(packet: bytes) -> tuple[Optional[int], Optional[int]]:
    if len(packet) < 14:
        return None, None
    eth_type = int.from_bytes(packet[12:14], "big")
    offset = 14
    if eth_type == 0x8100 and len(packet) >= 18:
        eth_type = int.from_bytes(packet[16:18], "big")
        offset = 18

    if eth_type == 0x0800:
        if len(packet) < offset + 20:
            return None, None
        ihl = (packet[offset] & 0x0F) * 4
        if len(packet) < offset + ihl + 4:
            return None, None
        proto = packet[offset + 9]
        if proto not in (6, 17):
            return None, None
        l4 = offset + ihl
        return int.from_bytes(packet[l4 : l4 + 2], "big"), int.from_bytes(packet[l4 + 2 : l4 + 4], "big")

    if eth_type == 0x86DD:
        if len(packet) < offset + 40 + 4:
            return None, None
        next_header = packet[offset + 6]
        if next_header not in (6, 17):
            return None, None
        l4 = offset + 40
        return int.from_bytes(packet[l4 : l4 + 2], "big"), int.from_bytes(packet[l4 + 2 : l4 + 4], "big")

    return None, None


class PreCaptureManager:
    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None:
        self._lock = threading.Lock()
        self._buffer: Deque[tuple[float, bytes]] = deque()
        self._bytes = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._bpf = None
        self._sock_fd: Optional[int] = None

        self._enabled = True
        self._mode = "disabled"  # disabled | pre_capture | post_only
        self._reason = "not started"
        self._iface: Optional[str] = None
        self._source_path = str((Path(__file__).resolve().parent.parent / "sensors" / "ebpf" / "net_capture.bpf.c"))
        self._snaplen = 65535
        self._max_buffer_mb = 64
        self._pre_seconds = 30.0
        self._post_seconds = 30.0
        self._min_memory_mb = 512
        self._ports: set[int] = set()
        self._running = False

        if config is not None:
            self.configure(config)

    def configure(self, config: Mapping[str, Any]) -> None:
        forensics_cfg = config.get("forensics", {}) if hasattr(config, "get") else {}
        pcap_cfg = forensics_cfg.get("pcap_precapture", {}) if isinstance(forensics_cfg, dict) else {}
        self._enabled = bool(pcap_cfg.get("enabled", True))
        self._iface = str(pcap_cfg.get("interface", "")).strip() or None
        self._source_path = str(pcap_cfg.get("ebpf_program", self._source_path))
        self._snaplen = max(256, int(pcap_cfg.get("snaplen", 65535)))
        self._max_buffer_mb = max(8, int(pcap_cfg.get("max_buffer_mb", 64)))
        self._pre_seconds = max(0.0, float(pcap_cfg.get("pre_seconds", 30)))
        self._post_seconds = max(0.0, float(pcap_cfg.get("post_seconds", 30)))
        self._min_memory_mb = max(128, int(pcap_cfg.get("min_memory_mb_for_precapture", 512)))
        ports = pcap_cfg.get("capture_ports", [])
        if isinstance(ports, list):
            self._ports = {int(p) for p in ports if str(p).isdigit()}
        else:
            self._ports = set()

    def start(self) -> None:
        if self._running:
            return
        if not self._enabled:
            self._mode = "disabled"
            self._reason = "disabled by configuration"
            return
        memory_mb = _memory_total_mb()
        if memory_mb is not None and memory_mb < self._min_memory_mb:
            self._mode = "post_only"
            self._reason = f"low_memory:{memory_mb}MB"
            return
        ok, reason = self._start_capture_socket()
        if ok:
            self._mode = "pre_capture"
            self._reason = ""
            self._running = True
            self._stop.clear()
            self._thread = threading.Thread(target=self._capture_loop, daemon=True, name="phantom-precapture")
            self._thread.start()
            return
        self._mode = "post_only"
        self._reason = reason

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._close_socket()
        self._running = False

    def reload(self, config: Mapping[str, Any]) -> None:
        self.stop()
        self.configure(config)
        self.start()

    def status(self) -> dict[str, Any]:
        return {
            "mode": self._mode,
            "running": self._running,
            "reason": self._reason,
            "interface": self._iface,
            "max_buffer_mb": self._max_buffer_mb,
            "pre_seconds": self._pre_seconds,
            "post_seconds": self._post_seconds,
        }

    def export_window(
        self,
        output_path: str,
        event_time: datetime,
        pre_seconds: Optional[float] = None,
        post_seconds: Optional[float] = None,
        deadline_seconds: Optional[float] = None,
    ) -> bool:
        if not self._enabled:
            return False
        if not self._running and self._mode == "disabled":
            self.start()

        pre = self._pre_seconds if pre_seconds is None else max(0.0, float(pre_seconds))
        post = self._post_seconds if post_seconds is None else max(0.0, float(post_seconds))

        if self._running:
            wait_for = post
            if deadline_seconds is not None:
                wait_for = min(wait_for, max(0.0, float(deadline_seconds) - 0.5))
            if wait_for > 0:
                time.sleep(wait_for)
            event_ts = event_time.timestamp()
            packets = self._snapshot(event_ts - pre, event_ts + post)
            if not packets:
                return False
            self._write_pcap(output_path, packets)
            return True

        # Режим post_only: короткий живой захват без предварительного буфера.
        if self._mode == "post_only":
            duration = post
            if deadline_seconds is not None:
                duration = min(duration, max(0.0, float(deadline_seconds) - 0.5))
            packets = self._capture_post_only(duration)
            if not packets:
                return False
            self._write_pcap(output_path, packets)
            return True
        return False

    def _capture_loop(self) -> None:
        if self._sock_fd is None:
            return
        max_bytes = self._max_buffer_mb * 1024 * 1024
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._sock_fd], [], [], 0.2)
                if not ready:
                    continue
                packet = os.read(self._sock_fd, self._snaplen)
                if not packet:
                    continue
                if not self._packet_allowed(packet):
                    continue
                ts = time.time()
                with self._lock:
                    self._buffer.append((ts, packet))
                    self._bytes += len(packet)
                    while self._bytes > max_bytes and self._buffer:
                        _old_ts, old_packet = self._buffer.popleft()
                        self._bytes -= len(old_packet)
            except BlockingIOError:
                continue
            except Exception:
                if self._stop.is_set():
                    break
                continue

    def _snapshot(self, start_ts: float, end_ts: float) -> list[tuple[float, bytes]]:
        with self._lock:
            return [(ts, pkt) for ts, pkt in self._buffer if start_ts <= ts <= end_ts]

    def _capture_post_only(self, duration: float) -> list[tuple[float, bytes]]:
        if duration <= 0:
            return []
        with self._lock:
            if self._sock_fd is not None:
                return []
            ok, reason = self._start_capture_socket()
            if not ok:
                self._reason = reason
                return []
        deadline = time.monotonic() + duration
        packets: list[tuple[float, bytes]] = []
        try:
            while time.monotonic() < deadline:
                if self._sock_fd is None:
                    break
                timeout = max(0.0, min(0.2, deadline - time.monotonic()))
                ready, _, _ = select.select([self._sock_fd], [], [], timeout)
                if not ready:
                    continue
                packet = os.read(self._sock_fd, self._snaplen)
                if not packet or not self._packet_allowed(packet):
                    continue
                packets.append((time.time(), packet))
        except Exception:
            pass
        finally:
            self._close_socket()
        return packets

    def _start_capture_socket(self) -> tuple[bool, str]:
        iface = self._iface
        if iface in (None, "", "any"):
            iface = _resolve_default_iface()
        if not iface:
            return False, "network interface not found"
        source_path = Path(self._source_path)
        if not source_path.exists():
            return False, f"ebpf source not found: {source_path}"
        try:
            from bcc import BPF  # type: ignore

            text = source_path.read_text(encoding="utf-8")
            bpf = BPF(text=text)
            fn = bpf.load_func("packet_filter", BPF.SOCKET_FILTER)
            BPF.attach_raw_socket(fn, iface)
            self._bpf = bpf
            self._sock_fd = fn.sock
            os.set_blocking(self._sock_fd, False)
            self._iface = iface
            return True, ""
        except Exception as exc:
            self._bpf = None
            self._sock_fd = None
            return False, f"ebpf socket capture unavailable: {exc}"

    def _close_socket(self) -> None:
        if self._sock_fd is not None:
            try:
                os.close(self._sock_fd)
            except OSError:
                pass
            self._sock_fd = None
        self._bpf = None

    def _packet_allowed(self, packet: bytes) -> bool:
        if not self._ports:
            return True
        src_port, dst_port = _extract_ports(packet)
        if src_port is None and dst_port is None:
            return False
        return (src_port in self._ports) or (dst_port in self._ports)

    def _write_pcap(self, output_path: str, packets: list[tuple[float, bytes]]) -> None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as fh:
            # Глобальный заголовок PCAP (little-endian)
            fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, self._snaplen, 1))
            for ts, packet in packets:
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1_000_000)
                incl = min(len(packet), self._snaplen)
                fh.write(struct.pack("<IIII", ts_sec, ts_usec, incl, len(packet)))
                fh.write(packet[:incl])


_MANAGER: Optional[PreCaptureManager] = None
_MANAGER_LOCK = threading.Lock()


def get_precapture_manager(config: Optional[Mapping[str, Any]] = None) -> PreCaptureManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = PreCaptureManager(config=config)
        elif config is not None:
            _MANAGER.configure(config)
    return _MANAGER

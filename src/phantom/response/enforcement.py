"""
Примитивы принудительного контроля процессов и сети.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from phantom.core.config import get_config

logger = logging.getLogger("phantom.enforcement")


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


class ProcessEnforcer:
    async def sigstop(self, pid: int) -> bool:
        return await asyncio.to_thread(self._send_signal, pid, signal.SIGSTOP)

    async def sigkill(self, pid: int) -> bool:
        return await asyncio.to_thread(self._send_signal, pid, signal.SIGKILL)

    async def sigcont(self, pid: int) -> bool:
        return await asyncio.to_thread(self._send_signal, pid, signal.SIGCONT)

    def _send_signal(self, pid: int, sig: signal.Signals) -> bool:
        # Защита: не трогаем init (PID 1) и невалидные PID
        if pid <= 1:
            logger.warning("Refused: attempt to send %s to PID=%s", sig.name, pid)
            return False
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            logger.warning("PID %s does not exist for signal %s", pid, sig.name)
            return False
        except PermissionError:
            logger.error("No permission to signal PID %s with %s", pid, sig.name)
            return False
        except Exception as exc:
            logger.error("Failed to send %s to PID %s: %s", sig.name, pid, exc)
            return False


class CgroupEbpfIsolator:
    """
    Сетевая изоляция процессов через cgroup eBPF хуки (блокировка ingress/egress).
    """

    def __init__(
        self,
        *,
        cgroup_root: str = "/sys/fs/cgroup",
        bpffs_root: str = "/sys/fs/bpf/phantom",
        source_path: Optional[str] = None,
    ) -> None:
        self._cgroup_root = Path(cgroup_root)
        self._quarantine_cg = self._cgroup_root / "phantom_quarantine"
        self._bpffs_root = Path(bpffs_root) / "cgroup_drop"
        self._source_path = Path(
            source_path
            or (Path(__file__).resolve().parent.parent / "sensors" / "ebpf" / "cgroup_drop.bpf.c")
        )
        self._lock = threading.Lock()
        self._loaded = False
        self._ingress_prog = self._bpffs_root / "drop_ingress"
        self._egress_prog = self._bpffs_root / "drop_egress"

    def initialize(self) -> None:
        with self._lock:
            if self._loaded:
                return
            if not self._source_path.exists():
                raise RuntimeError(f"cgroup eBPF source not found: {self._source_path}")
            if not self._cgroup_root.exists():
                raise RuntimeError("cgroup root not found")
            self._quarantine_cg.mkdir(parents=True, exist_ok=True)
            self._bpffs_root.mkdir(parents=True, exist_ok=True)
            self._load_and_attach()
            self._loaded = True

    def isolate_pid(self, pid: int, ttl_seconds: Optional[int] = None) -> bool:
        # Защита: не изолируем init и невалидные PID
        if pid <= 1:
            logger.warning("Refused: attempt to isolate PID=%s", pid)
            return False
        try:
            self.initialize()
        except Exception as exc:
            logger.error("cgroup eBPF init failed: %s", exc)
            return False

        target = self._quarantine_cg / f"pid-{pid}"
        origin_path = self._read_origin_path(pid)
        start_time = self._pid_starttime(pid)
        try:
            target.mkdir(parents=True, exist_ok=True)
            self._write_pid(target, pid)
            if ttl_seconds and ttl_seconds > 0 and origin_path is not None and start_time is not None:
                self._schedule_restore(pid, ttl_seconds, origin_path, start_time)
            return True
        except Exception as exc:
            logger.error("Failed to move PID %s to cgroup quarantine: %s", pid, exc)
            return False

    def _load_and_attach(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phantom-ebpf-") as td:
            obj = Path(td) / "cgroup_drop.bpf.o"
            compile_cmd = [
                "clang",
                "-O2",
                "-g",
                "-target",
                "bpf",
                "-c",
                str(self._source_path),
                "-o",
                str(obj),
            ]
            compile_res = self._run(compile_cmd, timeout=10)
            if not compile_res.ok:
                raise RuntimeError(f"clang failed: {compile_res.stderr.strip() or compile_res.stdout.strip()}")

            load_cmd = [
                "bpftool",
                "prog",
                "loadall",
                str(obj),
                str(self._bpffs_root),
                "type",
                "cgroup_skb",
            ]
            load_res = self._run(load_cmd, timeout=10)
            if not load_res.ok:
                raise RuntimeError(f"bpftool loadall failed: {load_res.stderr.strip() or load_res.stdout.strip()}")

        self._attach_prog(self._ingress_prog, "ingress")
        self._attach_prog(self._egress_prog, "egress")

    def _attach_prog(self, prog: Path, direction: str) -> None:
        cmd = [
            "bpftool",
            "cgroup",
            "attach",
            str(self._quarantine_cg),
            direction,
            "pinned",
            str(prog),
        ]
        res = self._run(cmd, timeout=5)
        if res.ok:
            return
        output = f"{res.stdout}\n{res.stderr}".lower()
        if "file exists" in output or "already" in output:
            return
        raise RuntimeError(f"bpftool cgroup attach {direction} failed: {res.stderr.strip() or res.stdout.strip()}")

    def _schedule_restore(self, pid: int, ttl_seconds: int, origin_path: Path, start_time: int) -> None:
        timer = threading.Timer(ttl_seconds, self._restore_pid, args=(pid, origin_path, start_time))
        timer.daemon = True
        timer.start()

    def _restore_pid(self, pid: int, origin_path: Path, expected_start_time: int) -> None:
        try:
            if not origin_path.exists():
                return
            if not Path(f"/proc/{pid}").exists():
                return
            current_start = self._pid_starttime(pid)
            if current_start is None or current_start != expected_start_time:
                return
            current_cgroup = self._current_cgroup_path(pid)
            if current_cgroup is None:
                return
            if current_cgroup.resolve() != self._quarantine_cg.resolve():
                return
            self._write_pid(origin_path, pid)
        except Exception:
            pass

    def _write_pid(self, cgroup_dir: Path, pid: int) -> None:
        procs = cgroup_dir / "cgroup.procs"
        procs.write_text(f"{pid}\n", encoding="utf-8")

    def _read_origin_path(self, pid: int) -> Optional[Path]:
        try:
            text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        rel = self._parse_unified_cgroup(text)
        if not rel:
            return None
        return self._cgroup_root / rel.lstrip("/")

    def _current_cgroup_path(self, pid: int) -> Optional[Path]:
        try:
            text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        rel = self._parse_unified_cgroup(text)
        if not rel:
            return None
        return self._cgroup_root / rel.lstrip("/")

    def _pid_starttime(self, pid: int) -> Optional[int]:
        try:
            text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        if ")" not in text:
            return None
        # Формат: pid (comm) state ...; берём поля после ')'
        rest = text.split(")", 1)[1].strip()
        parts = rest.split()
        if len(parts) < 20:
            return None
        val = parts[19]
        if not val.isdigit():
            return None
        return int(val)

    def _parse_unified_cgroup(self, text: str) -> Optional[str]:
        for line in text.splitlines():
            if "::" in line:
                return line.split("::", 1)[1].strip()
        return None

    def _run(self, cmd: list[str], timeout: float) -> CommandResult:
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return CommandResult(ok=False, stderr=f"{cmd[0]} not found")
        except subprocess.TimeoutExpired:
            return CommandResult(ok=False, stderr=f"{cmd[0]} timeout")
        except Exception as exc:
            return CommandResult(ok=False, stderr=str(exc))
        return CommandResult(
            ok=(proc.returncode == 0),
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
        )


class NetworkEnforcer:
    """
    Сетевая изоляция и чёрный список IP через nftables.
    """

    def __init__(
        self,
        table: str = "phantom",
        family: str = "inet",
        ipv4_set: str = "blocked_ipv4",
        ipv6_set: str = "blocked_ipv6",
        uid_set: str = "blocked_uids",
    ) -> None:
        self.family = family
        self.table = table
        self.ipv4_set = ipv4_set
        self.ipv6_set = ipv6_set
        self.uid_set = uid_set
        self._ebpf_isolator = CgroupEbpfIsolator()
        self._nft_missing_logged = False
        self._base_ready = False
        self._base_lock = threading.Lock()
        self._allow_uid_fallback = False
        try:
            cfg = get_config()
            enforcement_cfg = cfg.get("enforcement", {})
            if not isinstance(enforcement_cfg, dict):
                enforcement_cfg = {}
            self._allow_uid_fallback = bool(enforcement_cfg.get("allow_uid_fallback", False))
        except Exception:
            self._allow_uid_fallback = False
        env_override = os.getenv("PHANTOM_ALLOW_UID_FALLBACK")
        if env_override is not None:
            self._allow_uid_fallback = env_override.strip().lower() in {"1", "true", "yes", "on"}

    async def initialize(self) -> None:
        await asyncio.to_thread(self._ensure_base)
        await asyncio.to_thread(self._init_ebpf)

    async def block_ips(self, ips: Iterable[str], ttl_seconds: Optional[int] = None) -> bool:
        ip_list = [ip for ip in ips if ip]
        if not ip_list:
            return True
        return await asyncio.to_thread(self._block_ips_sync, ip_list, ttl_seconds)

    async def isolate_process(self, pid: int, ttl_seconds: Optional[int] = None) -> bool:
        return await asyncio.to_thread(self._isolate_process_sync, pid, ttl_seconds)

    def _init_ebpf(self) -> None:
        try:
            self._ebpf_isolator.initialize()
        except Exception as exc:
            logger.warning("cgroup eBPF isolation unavailable, fallback nft only: %s", exc)

    def _ensure_base(self) -> None:
        if self._base_ready:
            return
        with self._base_lock:
            if self._base_ready:
                return
            self._run_nft(["add", "table", self.family, self.table], tolerate_errors=True)
            self._run_nft(
                [
                    "add",
                    "set",
                    self.family,
                    self.table,
                    self.ipv4_set,
                    "{ type ipv4_addr; flags timeout; }",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "set",
                    self.family,
                    self.table,
                    self.ipv6_set,
                    "{ type ipv6_addr; flags timeout; }",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "set",
                    self.family,
                    self.table,
                    self.uid_set,
                    "{ type uid; flags timeout; }",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "chain",
                    self.family,
                    self.table,
                    "input",
                    "{ type filter hook input priority 0 ; policy accept ; }",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "chain",
                    self.family,
                    self.table,
                    "output",
                    "{ type filter hook output priority 0 ; policy accept ; }",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "rule",
                    self.family,
                    self.table,
                    "output",
                    "meta",
                    "skuid",
                    f"@{self.uid_set}",
                    "drop",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "rule",
                    self.family,
                    self.table,
                    "output",
                    "ip",
                    "daddr",
                    f"@{self.ipv4_set}",
                    "drop",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "rule",
                    self.family,
                    self.table,
                    "input",
                    "ip",
                    "saddr",
                    f"@{self.ipv4_set}",
                    "drop",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "rule",
                    self.family,
                    self.table,
                    "output",
                    "ip6",
                    "daddr",
                    f"@{self.ipv6_set}",
                    "drop",
                ],
                tolerate_errors=True,
            )
            self._run_nft(
                [
                    "add",
                    "rule",
                    self.family,
                    self.table,
                    "input",
                    "ip6",
                    "saddr",
                    f"@{self.ipv6_set}",
                    "drop",
                ],
                tolerate_errors=True,
            )
            self._base_ready = True

    def _block_ips_sync(self, ips: list[str], ttl_seconds: Optional[int]) -> bool:
        self._ensure_base()
        failures = 0
        for ip in ips:
            set_name = self._ip_set_name(ip)
            if not set_name:
                failures += 1
                logger.error("Unsupported IP for blacklist: %s", ip)
                continue
            if ttl_seconds and ttl_seconds > 0:
                element = f"{ip} timeout {ttl_seconds}s"
            else:
                element = ip
            res = self._run_nft(
                ["add", "element", self.family, self.table, set_name, "{ " + element + " }"],
                tolerate_errors=False,
            )
            if not res.ok:
                if "file exists" in (res.stderr or "").lower():
                    continue
                failures += 1
                logger.error("Failed to block IP %s: %s", ip, res.stderr.strip())
        return failures == 0

    def _isolate_process_sync(self, pid: int, ttl_seconds: Optional[int]) -> bool:
        ebpf_ok = self._ebpf_isolator.isolate_pid(pid, ttl_seconds=ttl_seconds)
        if ebpf_ok:
            return True
        if not self._allow_uid_fallback:
            logger.error("UID-level fallback disabled; isolation skipped for PID %s", pid)
            return False
        uid = self._pid_uid(pid)
        if uid is None:
            logger.error("Unable to resolve UID for PID %s", pid)
            return False
        self._ensure_base()
        if ttl_seconds and ttl_seconds > 0:
            element = f"{uid} timeout {ttl_seconds}s"
        else:
            element = str(uid)
        res = self._run_nft(
            ["add", "element", self.family, self.table, self.uid_set, "{ " + element + " }"],
            tolerate_errors=False,
        )
        if not res.ok:
            if "file exists" in (res.stderr or "").lower():
                return True
            logger.error("Failed to isolate PID %s via UID %s: %s", pid, uid, res.stderr.strip())
            return False
        return True

    def _ip_set_name(self, ip: str) -> Optional[str]:
        try:
            value = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if value.version == 4:
            return self.ipv4_set
        return self.ipv6_set

    def _pid_uid(self, pid: int) -> Optional[int]:
        status_path = f"/proc/{pid}/status"
        try:
            with open(status_path, "rt", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if not line.startswith("Uid:"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
        except Exception:
            return None
        return None

    def _run_nft(self, args: list[str], tolerate_errors: bool) -> CommandResult:
        cmd = ["nft", *args]
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=2.0,
            )
        except FileNotFoundError:
            if not self._nft_missing_logged:
                logger.error("nft not found in PATH")
                self._nft_missing_logged = True
            return CommandResult(ok=False, stderr="nft not found")
        except subprocess.TimeoutExpired:
            return CommandResult(ok=False, stderr="nft timeout")
        except Exception as exc:
            return CommandResult(ok=False, stderr=str(exc))

        ok = proc.returncode == 0
        if not ok and not tolerate_errors:
            logger.debug("nft command failed: %s", " ".join(cmd))
        return CommandResult(ok=ok, stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)

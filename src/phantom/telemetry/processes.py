"""
Process telemetry collector.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from phantom.core.state import ProcessInfo
from phantom.core.config import get_config


class ProcessCollector:
    def __init__(self) -> None:
        self._collect_env = False
        self._env_allowlist: set[str] = set()
        self._env_deny_re = re.compile(
            r"(PASS|PASSWORD|SECRET|TOKEN|API[_-]?KEY|KEY|CRED|AUTH|COOKIE|SESSION|PRIVATE|SSH|AWS_|AZURE_|GCP_|GOOGLE_|SLACK_|GITHUB_|GITLAB_)",
            re.IGNORECASE,
        )
        self._max_env_entries = 200
        self._max_env_value_len = 1024

        try:
            cfg = get_config()
            telemetry_cfg = cfg.get("telemetry", {}) if hasattr(cfg, "get") else {}
            proc_cfg = telemetry_cfg
            if isinstance(telemetry_cfg, dict) and "process" in telemetry_cfg:
                proc_cfg = telemetry_cfg.get("process", {})

            if isinstance(proc_cfg, dict):
                self._collect_env = bool(proc_cfg.get("collect_env", False))
                allowlist = proc_cfg.get("env_allowlist", [])
                if isinstance(allowlist, (list, tuple, set)):
                    self._env_allowlist = {str(k).upper() for k in allowlist if str(k).strip()}
                denylist = proc_cfg.get("env_denylist")
                if isinstance(denylist, (list, tuple, set)):
                    joined = "|".join(re.escape(str(k)) for k in denylist if str(k).strip())
                    if joined:
                        self._env_deny_re = re.compile(joined, re.IGNORECASE)
                max_entries = proc_cfg.get("max_env_entries")
                if isinstance(max_entries, int) and max_entries > 0:
                    self._max_env_entries = max_entries
                max_value_len = proc_cfg.get("max_env_value_len")
                if isinstance(max_value_len, int) and max_value_len > 0:
                    self._max_env_value_len = max_value_len
        except Exception:
            # Fail-safe: do not collect env on errors.
            self._collect_env = False
    async def collect(self, pid: int) -> Optional[ProcessInfo]:
        return await asyncio.to_thread(self._collect_sync, pid)

    def _collect_sync(self, pid: int) -> Optional[ProcessInfo]:
        try:
            import psutil  # type: ignore
        except Exception:
            return self._collect_via_ps(pid)

        try:
            proc = psutil.Process(pid)
            argv = tuple(proc.cmdline())
            env = self._safe_env(proc)
            ancestors = tuple(parent.name() for parent in proc.parents())
            return ProcessInfo(
                pid=pid,
                ppid=proc.ppid(),
                name=proc.name(),
                exe=self._safe_call(proc.exe),
                cmdline=" ".join(argv),
                argv=argv,
                environ=env,
                cwd=self._safe_call(proc.cwd),
                root=self._read_proc_link(pid, "root"),
                user=self._safe_call(proc.username),
                uid=proc.uids().real if hasattr(proc, "uids") else None,
                gid=proc.gids().real if hasattr(proc, "gids") else None,
                start_time=datetime.fromtimestamp(proc.create_time(), tz=timezone.utc),
                ancestors=ancestors,
                pid_ns=self._namespace_inode(pid, "pid"),
                mnt_ns=self._namespace_inode(pid, "mnt"),
            )
        except Exception:
            return None

    def _collect_via_ps(self, pid: int) -> Optional[ProcessInfo]:
        try:
            out = subprocess.check_output(
                ["ps", "-o", "pid=,ppid=,user=,command=", "-p", str(pid)],
                text=True,
            ).strip()
        except Exception:
            return None
        if not out:
            return None
        try:
            pid_val, ppid_val, user, cmd = out.split(None, 3)
            argv = tuple(shlex.split(cmd))
            return ProcessInfo(
                pid=int(pid_val),
                ppid=int(ppid_val),
                name=os.path.basename(argv[0]) if argv else "unknown",
                cmdline=cmd,
                argv=argv,
                user=user,
                root=self._read_proc_link(int(pid_val), "root"),
                pid_ns=self._namespace_inode(int(pid_val), "pid"),
                mnt_ns=self._namespace_inode(int(pid_val), "mnt"),
            )
        except Exception:
            return None

    def _safe_env(self, proc: object) -> Dict[str, str]:
        try:
            if not self._collect_env:
                return {}
            data = proc.environ()  # type: ignore[attr-defined]
            if not isinstance(data, dict):
                return {}
            result: Dict[str, str] = {}
            for key, value in data.items():
                skey = str(key)
                if self._env_allowlist and skey.upper() not in self._env_allowlist:
                    continue
                if self._env_deny_re.search(skey):
                    continue
                if self._max_env_entries and len(result) >= self._max_env_entries:
                    break
                sval = str(value)
                if self._max_env_value_len and len(sval) > self._max_env_value_len:
                    sval = sval[: self._max_env_value_len] + "..."
                result[skey] = sval
            return result
        except Exception:
            return {}

    def _safe_call(self, fn) -> Optional[str]:
        try:
            value = fn()
            return str(value) if value is not None else None
        except Exception:
            return None

    def _read_proc_link(self, pid: int, name: str) -> Optional[str]:
        try:
            return os.readlink(f"/proc/{pid}/{name}")
        except Exception:
            return None

    def _namespace_inode(self, pid: int, ns: str) -> Optional[int]:
        try:
            target = Path(f"/proc/{pid}/ns/{ns}")
            link = os.readlink(target)
            if "[" in link and "]" in link:
                return int(link.split("[", 1)[1].rstrip("]"))
        except Exception:
            return None
        return None

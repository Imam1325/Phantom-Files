"""
Коллектор криминалистических данных с ограниченным SLA и метаданными целостности.
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from phantom.core.config import get_config, get_path
from phantom.core.state import Context
from phantom.telemetry.precapture import get_precapture_manager
from phantom.response.sandbox import SandboxRunner
from phantom.response.storage import EvidenceStorage
from phantom.utils.crypto import md5_file, sha1_file, sha256_file, sign_ed25519
from phantom.utils.fs import safe_mkdirs

logger = logging.getLogger("phantom.forensics")


class _IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class ForensicsCollector:
    def __init__(self) -> None:
        try:
            base = get_path("evidence_dir")
        except Exception:
            try:
                base = get_path("logs_dir")
            except Exception:
                base = "/tmp/phantom_evidence"
        self._base = Path(base)
        safe_mkdirs(str(self._base))

        cfg = get_config()
        forensics_cfg = cfg.get("forensics", {})
        signing_cfg = cfg.get("signing", {})

        self._max_seconds = int(forensics_cfg.get("timeout_seconds", 60))
        self._memory_dump_enabled = bool(forensics_cfg.get("memory_dump", True))
        self._chain_state_file = Path(str(forensics_cfg.get("chain_state_file", self._base / "chain_state.json")))
        pcap_cfg = forensics_cfg.get("pcap_precapture", {})
        self._pcap_enabled = bool(pcap_cfg.get("enabled", True))
        self._pcap_pre_seconds = float(pcap_cfg.get("pre_seconds", 30))
        self._pcap_post_seconds = float(pcap_cfg.get("post_seconds", 30))
        self._precapture = get_precapture_manager(cfg)

        self._signing_key_path = signing_cfg.get("ed25519_private_key_path")
        self._signing_passphrase = signing_cfg.get("ed25519_passphrase_env")
        self._storage = EvidenceStorage()
        self._chain_lock = threading.Lock()
        sandbox_cfg = cfg.get("sandbox", {})
        self._sandbox_enabled = bool(sandbox_cfg.get("enabled", False))
        self._sandbox = SandboxRunner()

    async def collect(self, context: Context, params: Optional[Dict[str, Any]] = None) -> List[str]:
        params = params or {}
        deadline = time.monotonic() + min(self._max_seconds, int(params.get("timeout_seconds", self._max_seconds)))

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        event_id = context.event.event_id
        incident_id = context.incident_id or "unknown"
        bundle_name = f"evidence-{incident_id}-{event_id}-{ts}.tar.gz"
        bundle_path = self._base / bundle_name

        with tempfile.TemporaryDirectory(prefix="phantom_evidence_") as tmp_dir:
            work = Path(tmp_dir)
            await self._collect_metadata(context, work, deadline)
            await self._collect_process_artifacts(context, work, deadline)
            await self._collect_network_snapshot(context, work, deadline)
            await self._collect_sandbox(context, work, deadline, params)

            await asyncio.to_thread(self._build_bundle, work, bundle_path)
            manifest_path = await asyncio.to_thread(self._append_integrity_manifest, bundle_path)
            await asyncio.to_thread(self._set_immutable_best_effort, bundle_path)
            await asyncio.to_thread(self._set_immutable_best_effort, manifest_path)
            uploaded = await asyncio.to_thread(self._storage.store, bundle_path, manifest_path)

        artifacts = [str(bundle_path), str(manifest_path)]
        artifacts.extend(uploaded)
        return artifacts

    async def _collect_metadata(self, context: Context, work: Path, deadline: float) -> None:
        if time.monotonic() >= deadline:
            return
        metadata = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
            "kernel": os.uname().release if hasattr(os, "uname") else "unknown",
            "uptime_seconds": self._read_uptime(),
            "context": context.to_dict(),
        }
        await asyncio.to_thread(self._write_json, work / "context.json", metadata)

    async def _collect_process_artifacts(self, context: Context, work: Path, deadline: float) -> None:
        pid = context.event.process_pid
        if not pid or time.monotonic() >= deadline:
            return

        proc_dir = Path(f"/proc/{pid}")
        out_dir = work / "process"
        out_dir.mkdir(parents=True, exist_ok=True)
        if not proc_dir.exists():
            await asyncio.to_thread(
                self._write_json,
                out_dir / "status.json",
                {"error": "process_not_found", "pid": pid},
            )
            return

        await asyncio.to_thread(self._copy_text_file, proc_dir / "status", out_dir / "status.txt")
        await asyncio.to_thread(self._copy_text_file, proc_dir / "cmdline", out_dir / "cmdline.txt", binary=True)
        await asyncio.to_thread(self._copy_text_file, proc_dir / "environ", out_dir / "environ.txt", binary=True)
        await asyncio.to_thread(self._copy_text_file, proc_dir / "maps", out_dir / "maps.txt")
        await asyncio.to_thread(self._copy_text_file, proc_dir / "cgroup", out_dir / "cgroup.txt")
        await asyncio.to_thread(self._dump_fd_links, proc_dir / "fd", out_dir / "fd_links.json")
        await asyncio.to_thread(self._dump_ns_ids, proc_dir / "ns", out_dir / "namespaces.json")
        await asyncio.to_thread(self._dump_exe_metadata, proc_dir / "exe", out_dir / "exe_metadata.json")
        await asyncio.to_thread(self._dump_container_metadata, out_dir / "cgroup.txt", out_dir / "container.json")

        if self._memory_dump_enabled and time.monotonic() < deadline:
            await self._collect_memory_dump(pid, proc_dir, out_dir, deadline)

    async def _collect_sandbox(
        self,
        context: Context,
        work: Path,
        deadline: float,
        params: Dict[str, Any],
    ) -> None:
        if time.monotonic() >= deadline:
            return
        sandbox_params = dict(params.get("sandbox", {})) if isinstance(params, dict) else {}
        enabled = sandbox_params.pop("enabled", None)
        if enabled is None:
            enabled = self._sandbox_enabled
        if not enabled:
            return
        out_dir = work / "sandbox"
        out_dir.mkdir(parents=True, exist_ok=True)
        remaining = max(1, int(deadline - time.monotonic()))
        timeout_override = sandbox_params.get("timeout_seconds")
        if timeout_override is None:
            sandbox_params["timeout_seconds"] = remaining
        else:
            try:
                sandbox_params["timeout_seconds"] = min(int(timeout_override), remaining)
            except (TypeError, ValueError):
                sandbox_params["timeout_seconds"] = remaining
        try:
            result = await self._sandbox.analyze(context, params=sandbox_params)
        except Exception as exc:
            await asyncio.to_thread(
                self._write_json,
                out_dir / "status.json",
                {"enabled": True, "status": "failed", "error": str(exc)},
            )
            return
        if result is None:
            await asyncio.to_thread(
                self._write_json,
                out_dir / "status.json",
                {"enabled": True, "status": "unavailable"},
            )
            return
        copied: list[str] = []
        for artifact in result.artifacts:
            try:
                src = Path(artifact)
                if not src.exists() or not src.is_file():
                    continue
                dest = out_dir / src.name
                shutil.copy2(src, dest)
                copied.append(dest.name)
            except Exception:
                continue
        payload = result.to_dict()
        payload["artifacts"] = copied
        await asyncio.to_thread(self._write_json, out_dir / "result.json", payload)

    async def _collect_memory_dump(self, pid: int, proc_dir: Path, out_dir: Path, deadline: float) -> None:
        dump_path = out_dir / f"mem-{pid}.bin"
        maps_path = proc_dir / "maps"
        process_vm_ok = await asyncio.to_thread(self._dump_memory_process_vm_readv, pid, maps_path, dump_path, deadline)
        if process_vm_ok:
            return
        proc_mem_ok = await asyncio.to_thread(self._dump_memory_proc_mem, proc_dir, dump_path, deadline)
        if proc_mem_ok:
            return
        if time.monotonic() >= deadline:
            return
        await asyncio.to_thread(self._dump_memory_fallback, pid, out_dir)

    def _dump_memory_process_vm_readv(self, pid: int, maps_path: Path, dump_path: Path, deadline: float) -> bool:
        if not maps_path.exists():
            return False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            reader = libc.process_vm_readv
            reader.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(_IOVec),
                ctypes.c_ulong,
                ctypes.POINTER(_IOVec),
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            reader.restype = ctypes.c_ssize_t
        except Exception:
            return False

        regions = self._readable_regions(maps_path)
        if not regions:
            return False
        try:
            with dump_path.open("wb") as out_file:
                chunk = 1024 * 1024
                for start, end in regions:
                    if time.monotonic() >= deadline:
                        return False
                    cursor = start
                    while cursor < end:
                        if time.monotonic() >= deadline:
                            return False
                        want = min(chunk, end - cursor)
                        buf = ctypes.create_string_buffer(want)
                        local = _IOVec(ctypes.cast(buf, ctypes.c_void_p), want)
                        remote = _IOVec(ctypes.c_void_p(cursor), want)
                        copied = int(reader(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0))
                        if copied <= 0:
                            break
                        out_file.write(buf.raw[:copied])
                        cursor += copied
            return dump_path.exists() and dump_path.stat().st_size > 0
        except Exception as exc:
            logger.warning("process_vm_readv memory dump failed: %s", exc)
            return False

    def _dump_memory_proc_mem(self, proc_dir: Path, dump_path: Path, deadline: float) -> bool:
        maps_path = proc_dir / "maps"
        mem_path = proc_dir / "mem"
        if not maps_path.exists() or not mem_path.exists():
            return False
        try:
            regions = self._readable_regions(maps_path)

            with mem_path.open("rb", buffering=0) as mem_file, dump_path.open("wb") as out_file:
                for start, end in regions:
                    if time.monotonic() >= deadline:
                        return False
                    try:
                        mem_file.seek(start)
                        remaining = end - start
                        chunk = 1024 * 1024
                        while remaining > 0:
                            if time.monotonic() >= deadline:
                                return False
                            data = mem_file.read(min(chunk, remaining))
                            if not data:
                                break
                            out_file.write(data)
                            remaining -= len(data)
                    except Exception:
                        continue
            return dump_path.exists() and dump_path.stat().st_size > 0
        except Exception as exc:
            logger.warning("/proc/<pid>/mem memory dump failed: %s", exc)
            return False

    def _dump_memory_fallback(self, pid: int, out_dir: Path) -> bool:
        gcore_base = out_dir / f"gcore-{pid}"
        commands = [
            ["gcore", "-o", str(gcore_base), str(pid)],
            ["avml", str(out_dir / f"avml-{pid}.lime"), "--pid", str(pid)],
            ["avml", "--pid", str(pid), "--output", str(out_dir / f"avml-{pid}.lime")],
        ]
        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
            except FileNotFoundError:
                continue
            except Exception as exc:
                logger.warning("Memory fallback command failed (%s): %s", " ".join(cmd), exc)
                continue
            if proc.returncode == 0:
                return True
            logger.warning("Memory fallback command error (%s): %s", " ".join(cmd), proc.stderr.strip())
        return False

    async def _collect_network_snapshot(self, context: Context, work: Path, deadline: float) -> None:
        if time.monotonic() >= deadline:
            return
        path = work / "network.json"
        payload: dict[str, Any] = {
            "event_pid": context.event.process_pid,
            "connections": [],
        }
        if context.network:
            payload["connections"] = [c.__dict__ for c in context.network.connections]
        await asyncio.to_thread(self._write_json, path, payload)

        if not self._pcap_enabled or time.monotonic() >= deadline:
            return
        pcap_path = work / "network_prepost.pcap"
        remaining = max(0.0, deadline - time.monotonic())
        exported = await asyncio.to_thread(
            self._precapture.export_window,
            str(pcap_path),
            context.event.timestamp,
            self._pcap_pre_seconds,
            self._pcap_post_seconds,
            remaining,
        )
        if not exported:
            logger.debug("Pre-capture PCAP not exported for event=%s", context.event.event_id)

    def _build_bundle(self, work: Path, bundle_path: Path) -> None:
        with tarfile.open(bundle_path, "w:gz") as tar:
            for item in sorted(work.rglob("*")):
                tar.add(item, arcname=str(item.relative_to(work)))

    def _append_integrity_manifest(self, bundle_path: Path) -> Path:
        md5 = md5_file(str(bundle_path))
        sha1 = sha1_file(str(bundle_path))
        sha256 = sha256_file(str(bundle_path))
        manifest_path = bundle_path.with_suffix(bundle_path.suffix + ".manifest.json")

        try:
            with self._chain_lock:
                with self._chain_state_guard() as fh:
                    chain_prev = self._load_chain_state(fh)
                    chain_hash = self._compute_chain_hash(chain_prev, sha256, bundle_path.name)

                    manifest = {
                        "artifact": str(bundle_path.name),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "md5": md5,
                        "sha1": sha1,
                        "sha256": sha256,
                        "previous_hash": chain_prev,
                        "chain_hash": chain_hash,
                    }

                    signature = self._sign_manifest(manifest)
                    if signature:
                        manifest["ed25519_signature_b64"] = signature

                    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
                    if chain_hash:
                        self._save_chain_state(str(chain_hash), fh)
        except Exception:
            logger.warning("Chain state lock failed; writing manifest without chain integrity")
            manifest = {
                "artifact": str(bundle_path.name),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
                "previous_hash": None,
                "chain_hash": None,
            }
            signature = self._sign_manifest(manifest)
            if signature:
                manifest["ed25519_signature_b64"] = signature
            manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        return manifest_path

    def _compute_chain_hash(self, previous_hash: Optional[str], artifact_hash: Optional[str], name: str) -> Optional[str]:
        if not artifact_hash:
            return None
        payload = {
            "artifact": name,
            "sha256": artifact_hash,
            "previous_hash": previous_hash or "",
        }
        data = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _sign_manifest(self, manifest: dict) -> Optional[str]:
        if not self._signing_key_path:
            return None
        key_path = Path(str(self._signing_key_path))
        if not key_path.exists():
            logger.error("Signing key file not found: %s", key_path)
            return None
        try:
            key_data = key_path.read_bytes()
            passphrase = None
            if self._signing_passphrase:
                passphrase = os.getenv(str(self._signing_passphrase))
            payload = json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode("utf-8")
            sig = sign_ed25519(key_data, payload, passphrase=passphrase)
            return base64.b64encode(sig).decode("ascii")
        except Exception as exc:
            logger.error("Failed to sign evidence manifest: %s", exc)
            return None

    def _load_chain_state(self, fh: Optional[object] = None) -> Optional[str]:
        try:
            if fh is not None:
                fh.seek(0)
                text = fh.read()
                if not text:
                    return None
                data = json.loads(text)
            else:
                data = json.loads(self._chain_state_file.read_text(encoding="utf-8"))
            return str(data.get("last_hash"))
        except Exception:
            return None

    def _save_chain_state(self, value: str, fh: Optional[object] = None) -> None:
        payload = {"last_hash": value, "updated_at": datetime.now(timezone.utc).isoformat()}
        if fh is None:
            self._chain_state_file.parent.mkdir(parents=True, exist_ok=True)
            self._chain_state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(json.dumps(payload, indent=2))
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except Exception:
                pass
        except Exception:
            pass

    @contextmanager
    def _chain_state_guard(self):
        try:
            self._chain_state_file.parent.mkdir(parents=True, exist_ok=True)
            with self._chain_state_file.open("a+", encoding="utf-8") as fh:
                try:
                    import fcntl  # type: ignore

                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
                yield fh
                try:
                    import fcntl  # type: ignore

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
        except Exception as exc:
            logger.error("Failed to acquire chain state file lock: %s", exc)
            raise

    def _read_uptime(self) -> Optional[float]:
        try:
            first = Path("/proc/uptime").read_text(encoding="utf-8").split()[0]
            return float(first)
        except Exception:
            return None

    def _copy_text_file(self, src: Path, dst: Path, binary: bool = False) -> None:
        try:
            if binary:
                raw = src.read_bytes().replace(b"\x00", b"\n")
                dst.write_bytes(raw)
            else:
                dst.write_text(src.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        except Exception as exc:
            dst.write_text(f"error: {exc}\n", encoding="utf-8")

    def _dump_fd_links(self, fd_dir: Path, output: Path) -> None:
        payload: list[dict[str, Any]] = []
        if not fd_dir.exists():
            output.write_text("[]", encoding="utf-8")
            return
        for child in sorted(fd_dir.iterdir(), key=lambda p: p.name):
            try:
                payload.append({"fd": child.name, "target": os.readlink(str(child))})
            except Exception as exc:
                payload.append({"fd": child.name, "error": str(exc)})
        self._write_json(output, payload)

    def _dump_ns_ids(self, ns_dir: Path, output: Path) -> None:
        payload: dict[str, Any] = {}
        if not ns_dir.exists():
            self._write_json(output, payload)
            return
        for child in ns_dir.iterdir():
            try:
                payload[child.name] = os.readlink(str(child))
            except Exception as exc:
                payload[child.name] = f"error:{exc}"
        self._write_json(output, payload)

    def _dump_exe_metadata(self, exe_link: Path, output: Path) -> None:
        payload: dict[str, Any] = {}
        try:
            exe_path = Path(os.readlink(str(exe_link)))
            st = exe_path.stat()
            payload = {
                "path": str(exe_path),
                "inode": st.st_ino,
                "size": st.st_size,
                "md5": md5_file(str(exe_path)),
                "sha1": sha1_file(str(exe_path)),
                "sha256": sha256_file(str(exe_path)),
            }
            with exe_path.open("rb") as fh:
                payload["elf_magic_b64"] = base64.b64encode(fh.read(64)).decode("ascii")
        except Exception as exc:
            payload["error"] = str(exc)
        self._write_json(output, payload)

    def _dump_container_metadata(self, cgroup_file: Path, output: Path) -> None:
        payload: dict[str, Any] = {"runtime": None, "container_id": None}
        try:
            text = cgroup_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            payload["error"] = str(exc)
            self._write_json(output, payload)
            return

        for line in text.splitlines():
            if "docker/" in line:
                payload["runtime"] = "docker"
                payload["container_id"] = line.rsplit("docker/", 1)[-1].split("/", 1)[0]
                break
            if "kubepods" in line:
                payload["runtime"] = "kubernetes"
                payload["container_id"] = line.rsplit("/", 1)[-1]
                break
        self._write_json(output, payload)

    def _readable_regions(self, maps_path: Path) -> list[tuple[int, int]]:
        regions: list[tuple[int, int]] = []
        try:
            lines = maps_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return regions
        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            address, perms = parts[0], parts[1]
            if "r" not in perms:
                continue
            try:
                start_hex, end_hex = address.split("-")
                regions.append((int(start_hex, 16), int(end_hex, 16)))
            except Exception:
                continue
        return regions

    def _set_immutable_best_effort(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            subprocess.run(
                ["chattr", "+i", str(path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except Exception:
            return

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

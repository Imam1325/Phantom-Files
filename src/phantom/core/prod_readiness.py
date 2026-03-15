"""
Проверки готовности к продакшну.

Находится внутри пакета, чтобы операторы могли запускать `phantomctl prod-check`
без наличия папки `tools/` репозитория на диске.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REQUIRED_CAPS = {"CAP_BPF", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_KILL"}
REQUIRED_CMDS = ("python3", "nft", "setcap", "getcap", "systemctl")
EBPF_CMDS = ("clang", "bpftool")
REQUIRED_GROUPS = ("phantom-admin", "phantom-user")


@dataclass
class CheckResult:
    name: str
    status: str  # pass | warn | fail
    detail: str


def _parse_kernel_version(version: str) -> tuple[int, int, int]:
    parts: list[int] = []
    for chunk in version.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _file_mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        return 1, "", str(exc)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _check_os_kernel(results: list[CheckResult]) -> None:
    system = platform.system()
    release = platform.release()
    if system != "Linux":
        results.append(CheckResult("os", "fail", f"Expected Linux, got {system} {release}"))
        return
    ver = _parse_kernel_version(release)
    if ver < (5, 10, 0):
        results.append(CheckResult("kernel", "fail", f"Kernel must be >= 5.10, got {release}"))
        return
    results.append(CheckResult("os", "pass", f"Linux {release}"))


def _check_commands(results: list[CheckResult], cfg: dict[str, Any] | None = None) -> None:
    cmds = list(REQUIRED_CMDS)
    # Команды eBPF требуются только при sensors.ebpf_enabled: true
    ebpf_enabled = False
    if isinstance(cfg, dict):
        sensors = cfg.get("sensors", {})
        if isinstance(sensors, dict):
            ebpf_enabled = bool(sensors.get("ebpf_enabled", False))
    if ebpf_enabled:
        cmds.extend(EBPF_CMDS)
    missing = [cmd for cmd in cmds if shutil.which(cmd) is None]
    if missing:
        results.append(CheckResult("commands", "fail", f"Missing commands: {', '.join(missing)}"))
    else:
        results.append(CheckResult("commands", "pass", "All required commands are present"))


def _check_cgroup_bpffs(results: list[CheckResult]) -> None:
    cgroup_root = Path("/sys/fs/cgroup")
    if not cgroup_root.exists():
        results.append(CheckResult("cgroup", "fail", "/sys/fs/cgroup is missing"))
        return
    controllers_file = cgroup_root / "cgroup.controllers"
    if not controllers_file.exists():
        results.append(CheckResult("cgroup", "fail", "cgroup v2 is required (missing cgroup.controllers)"))
    else:
        results.append(CheckResult("cgroup", "pass", "cgroup v2 detected"))

    bpffs = Path("/sys/fs/bpf")
    if bpffs.exists():
        results.append(CheckResult("bpffs", "pass", "/sys/fs/bpf present"))
    else:
        results.append(CheckResult("bpffs", "warn", "/sys/fs/bpf missing (mount bpffs for eBPF pinning)"))


def _check_users_groups(results: list[CheckResult]) -> None:
    rc, out, _err = _run(["id", "phantom"])
    if rc != 0:
        results.append(CheckResult("user", "fail", "User 'phantom' not found"))
    else:
        results.append(CheckResult("user", "pass", out))

    missing = []
    for group in REQUIRED_GROUPS:
        rc, _out, _err = _run(["getent", "group", group])
        if rc != 0:
            missing.append(group)
    if missing:
        results.append(CheckResult("groups", "fail", f"Missing groups: {', '.join(missing)}"))
    else:
        results.append(CheckResult("groups", "pass", "Required groups present"))


def _check_python(results: list[CheckResult]) -> None:
    py_ver = sys.version_info
    if (py_ver.major, py_ver.minor) < (3, 10):
        results.append(CheckResult("python", "fail", f"Python >= 3.10 required, got {platform.python_version()}"))
    else:
        results.append(CheckResult("python", "pass", f"Python {platform.python_version()}"))

    modules = ("bcc", "watchdog", "psutil", "yaml", "jinja2", "faker", "cryptography", "boto3")
    missing = []
    for mod in modules:
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    if missing:
        results.append(CheckResult("python_modules", "fail", f"Missing modules: {', '.join(missing)}"))
    else:
        results.append(CheckResult("python_modules", "pass", "Required Python modules available"))


def _check_service_file(results: list[CheckResult], service_path: Path) -> None:
    if not service_path.exists():
        results.append(CheckResult("service_file", "fail", f"Service file not found: {service_path}"))
        return
    text = service_path.read_text(encoding="utf-8", errors="ignore")
    cap_line = None
    for line in text.splitlines():
        if line.strip().startswith("CapabilityBoundingSet="):
            cap_line = line.split("=", 1)[1].strip()
            break
    if cap_line is None:
        results.append(CheckResult("service_caps", "fail", "CapabilityBoundingSet missing in service file"))
    else:
        caps = {token.strip() for token in cap_line.split() if token.strip()}
        missing_caps = sorted(REQUIRED_CAPS - caps)
        if missing_caps:
            results.append(CheckResult("service_caps", "fail", f"Missing capabilities: {', '.join(missing_caps)}"))
        else:
            results.append(CheckResult("service_caps", "pass", "Required capabilities declared"))


def _check_config(results: list[CheckResult], config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        results.append(CheckResult("config", "fail", f"Config not found: {config_path}"))
        return {}
    try:
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        results.append(CheckResult("config", "fail", f"Config parse failed: {exc}"))
        return {}
    if not isinstance(cfg, dict):
        results.append(CheckResult("config", "fail", "Config root must be a mapping"))
        return {}
    required_sections = ("paths", "sensors", "orchestrator", "forensics", "api")
    missing = [name for name in required_sections if name not in cfg]
    if missing:
        results.append(CheckResult("config_sections", "fail", f"Missing sections: {', '.join(missing)}"))
    else:
        results.append(CheckResult("config_sections", "pass", "Required sections found"))
    return cfg


def _check_paths_from_config(results: list[CheckResult], cfg: dict[str, Any]) -> None:
    paths = cfg.get("paths", {})
    if not isinstance(paths, dict):
        return
    critical = ("traps_dir", "logs_dir", "evidence_dir", "user_templates_dir")
    for key in critical:
        value = paths.get(key)
        if not isinstance(value, str) or not value.strip():
            results.append(CheckResult(f"path:{key}", "fail", "Missing or invalid path"))
            continue
        p = Path(value)
        if p.exists():
            writable = os.access(p, os.W_OK)
            status = "pass" if writable else "warn"
            results.append(CheckResult(f"path:{key}", status, f"{p} exists (writable={writable})"))
        else:
            results.append(CheckResult(f"path:{key}", "warn", f"{p} does not exist yet"))


def _check_secrets(results: list[CheckResult], cfg: dict[str, Any]) -> None:
    secrets_file = Path("/etc/phantom/secrets.env")
    if secrets_file.exists():
        mode = _file_mode(secrets_file)
        if mode == "0o400":
            results.append(CheckResult("secrets_env_perm", "pass", f"{secrets_file} mode={mode}"))
        else:
            results.append(CheckResult("secrets_env_perm", "warn", f"{secrets_file} mode={mode}, expected 0o400"))
    else:
        results.append(CheckResult("secrets_env_perm", "warn", f"{secrets_file} not found"))

    signing = cfg.get("signing", {})
    if isinstance(signing, dict):
        key_path = signing.get("ed25519_private_key_path")
        if isinstance(key_path, str) and key_path.strip():
            p = Path(key_path)
            if p.exists():
                mode = _file_mode(p)
                status = "pass" if mode in {"0o400", "0o600"} else "warn"
                results.append(CheckResult("signing_key_perm", status, f"{p} mode={mode}"))
            else:
                results.append(CheckResult("signing_key_perm", "warn", f"Signing key not found: {p}"))


def _summary(results: list[CheckResult]) -> dict[str, int]:
    counters = {"pass": 0, "warn": 0, "fail": 0}
    for item in results:
        counters[item.status] += 1
    return counters


def run_prod_readiness_check(*, config_path: str, service_path: str, json_output: bool) -> int:
    results: list[CheckResult] = []
    _check_os_kernel(results)
    cfg = _check_config(results, Path(config_path))
    _check_commands(results, cfg or None)
    _check_cgroup_bpffs(results)
    _check_users_groups(results)
    _check_python(results)
    _check_service_file(results, Path(service_path))
    if cfg:
        _check_paths_from_config(results, cfg)
        _check_secrets(results, cfg)

    counts = _summary(results)
    payload = {"summary": counts, "results": [item.__dict__ for item in results]}

    if json_output:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print("=== Phantom Production Readiness ===")
        for item in results:
            mark = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[item.status]
            print(f"[{mark}] {item.name}: {item.detail}")
        print(f"Summary: PASS={counts['pass']} WARN={counts['warn']} FAIL={counts['fail']}")

    return 0 if counts["fail"] == 0 else 2


"""
Утилиты начальной настройки системы.

Модуль автоматизирует продакшн-подготовку (пользователи, группы, каталоги),
чтобы операторам не приходилось делать это вручную.
"""

from __future__ import annotations

import os
import pwd
import grp
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from phantom.core.config import get_config


@dataclass(frozen=True)
class BootstrapPlan:
    user: str = "phantom"
    group_user: str = "phantom-user"
    group_admin: str = "phantom-admin"
    group_editor: str = "phantom-editor"
    home_dir: str = "/var/lib/phantom"
    shell: str = "/usr/sbin/nologin"


class BootstrapError(RuntimeError):
    pass


def _require_root() -> None:
    if os.geteuid() != 0:
        raise BootstrapError("Must run as root (use sudo)")


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        raise BootstrapError((proc.stderr or proc.stdout or "").strip() or f"Command failed: {cmd!r}")


def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def ensure_group(name: str, *, system: bool = True) -> bool:
    if _group_exists(name):
        return False
    args = ["groupadd"]
    if system:
        args.append("--system")
    args.append(name)
    _run(args)
    return True


def ensure_user(
    name: str,
    *,
    primary_group: str,
    extra_groups: Iterable[str] = (),
    home_dir: str,
    shell: str,
    system: bool = True,
) -> bool:
    if _user_exists(name):
        return False
    args = ["useradd"]
    if system:
        args.append("--system")
    args += ["--home", home_dir, "--shell", shell, "--gid", primary_group, "--create-home"]
    extras = [g for g in extra_groups if g]
    if extras:
        args += ["--groups", ",".join(extras)]
    args.append(name)
    _run(args)
    return True


def ensure_dir(path: str, *, owner_user: str, owner_group: str, mode: int) -> None:
    p = Path(path)
    try:
        p.lstat()
        if p.is_symlink():
            raise BootstrapError(f"Refusing to operate on symlink: {p}")
        if not p.is_dir():
            raise BootstrapError(f"Path exists but is not a directory: {p}")
    except FileNotFoundError:
        p.mkdir(parents=True, exist_ok=True)

    uid = pwd.getpwnam(owner_user).pw_uid
    gid = grp.getgrnam(owner_group).gr_gid
    os.chown(p, uid, gid)
    os.chmod(p, mode)


def _iter_bootstrap_dirs(cfg: dict) -> list[str]:
    paths = cfg.get("paths", {}) if isinstance(cfg, dict) else {}
    if not isinstance(paths, dict):
        return []

    candidates: list[str] = []
    for key in ("logs_dir", "traps_dir", "evidence_dir", "user_templates_dir"):
        val = paths.get(key)
        if isinstance(val, str) and val.strip():
            candidates.append(val)

    # Родительские каталоги для важных файлов (опционально в конфиге, но используются в рантайме)
    for key in ("trap_registry_file",):
        val = paths.get(key)
        if isinstance(val, str) and val.strip():
            candidates.append(str(Path(val).parent))

    chain_state = cfg.get("forensics", {}).get("chain_state_file") if isinstance(cfg.get("forensics", {}), dict) else None
    if isinstance(chain_state, str) and chain_state.strip():
        candidates.append(str(Path(chain_state).parent))

    # Создаём только абсолютные системные пути; относительные принадлежат разработчику.
    system_dirs: list[str] = []
    for raw in candidates:
        p = Path(raw)
        if p.is_absolute():
            system_dirs.append(str(p))
    return sorted(set(system_dirs))


def bootstrap(
    *,
    config_path: str,
    plan: BootstrapPlan = BootstrapPlan(),
    dry_run: bool = False,
) -> list[str]:
    """
    Обеспечивает наличие системных предусловий:
      - системные группы
      - сервисный пользователь
      - необходимые каталоги с безопасными правами

    Возвращает список выполненных (или запланированных для dry_run) действий.
    """
    actions: list[str] = []
    if not dry_run:
        _require_root()

    cfg = get_config(config_path, reload=True)
    dirs = _iter_bootstrap_dirs(dict(cfg))

    def _do(msg: str, fn) -> None:
        actions.append(msg)
        if not dry_run:
            fn()

    _do(f"ensure group: {plan.group_user}", lambda: ensure_group(plan.group_user))
    _do(f"ensure group: {plan.group_admin}", lambda: ensure_group(plan.group_admin))
    _do(f"ensure group: {plan.group_editor}", lambda: ensure_group(plan.group_editor))

    _do(
        f"ensure user: {plan.user}",
        lambda: ensure_user(
            plan.user,
            primary_group=plan.group_user,
            extra_groups=(plan.group_admin,),
            home_dir=plan.home_dir,
            shell=plan.shell,
        ),
    )

    # Базовые каталоги (создаём первыми, чтобы родители существовали).
    base_system_dirs = ["/var/lib/phantom", "/var/log/phantom", "/etc/phantom", "/etc/phantom/keys", "/etc/phantom/templates"]
    for d in base_system_dirs:
        if d not in dirs:
            dirs.append(d)

    # Политика владения:
    # - рантайм-данные/логи принадлежат phantom:phantom-user
    # - /etc/phantom принадлежит root, читается phantom-user
    for d in sorted(set(dirs)):
        p = Path(d)
        if str(p).startswith("/var/log/phantom") or str(p).startswith("/var/lib/phantom"):
            _do(
                f"ensure dir: {d} (phantom:{plan.group_user}, 0750)",
                lambda d=d: ensure_dir(d, owner_user=plan.user, owner_group=plan.group_user, mode=0o750),
            )
        elif str(p).startswith("/etc/phantom"):
            _do(
                f"ensure dir: {d} (root:{plan.group_user}, 0750)",
                lambda d=d: ensure_dir(d, owner_user="root", owner_group=plan.group_user, mode=0o750),
            )
        else:
            _do(
                f"skip non-system dir: {d}",
                lambda: None,
            )

    return actions


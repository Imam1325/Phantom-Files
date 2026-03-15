"""
CLI управления Phantom.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import getpass
import json
import logging
import os
import subprocess

from phantom.core.config import get_config, validate_config_for_daemon
from phantom.core.orchestrator import create_orchestrator
from phantom.core.bootstrap import BootstrapPlan, bootstrap
from phantom.factory.template_store import TemplateStore
from phantom.core.prod_readiness import run_prod_readiness_check

logger = logging.getLogger("phantom.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phantom control utility")
    parser.add_argument("--config", default="config/phantom.yaml", help="Path to phantom config")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("validate", help="Validate configuration and exit")
    prod = sub.add_parser("prod-check", help="Run production readiness checks")
    prod.add_argument("--service", default="deploy/phantom.service", help="Path to systemd unit file")
    prod.add_argument("--json", action="store_true", help="Output JSON")
    boot = sub.add_parser("bootstrap", help="Create phantom user/groups and directories")
    boot.add_argument("--dry-run", action="store_true", help="Print planned actions without changing system")

    sub.add_parser("run-once", help="Start orchestrator once (without sensors)")

    mode_parser = sub.add_parser("mode", help="View or change daemon run mode")
    mode_sub = mode_parser.add_subparsers(dest="mode_cmd")
    mode_sub.add_parser("get", help="Show current mode")
    mode_set = mode_sub.add_parser("set", help="Set daemon mode (requires root)")
    mode_set.add_argument("value", choices=["active", "observation", "dry_run"], help="Target mode")

    tpl = sub.add_parser("templates", help="Template store operations")
    tpl_sub = tpl.add_subparsers(dest="templates_cmd")
    tpl_sub.add_parser("list", help="List user templates")

    tpl_add = tpl_sub.add_parser("add", help="Add template")
    tpl_add.add_argument("--source", required=True, help="Source file path")
    tpl_add.add_argument("--name", required=True, help="Template name")
    tpl_add.add_argument("--version", required=True, help="SemVer version, e.g. v1.0.0")

    tpl_activate = tpl_sub.add_parser("activate", help="Activate template version")
    tpl_activate.add_argument("--name", required=True, help="Template name")
    tpl_activate.add_argument("--version", required=True, help="Template version")

    tpl_show = tpl_sub.add_parser("show", help="Show template details")
    tpl_show.add_argument("--name", required=True, help="Template name")

    tpl_remove = tpl_sub.add_parser("remove", help="Remove template or specific version")
    tpl_remove.add_argument("--name", required=True, help="Template name")
    tpl_remove.add_argument("--version", default=None, help="Specific version to remove (omit to remove all)")

    return parser


def _groups_for_user(username: str) -> set[str]:
    try:
        proc = subprocess.run(
            ["id", "-nG", username],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return set()
    if proc.returncode != 0:
        return set()
    return {g for g in proc.stdout.strip().split() if g}


def _resolve_local_role() -> str:
    """
    Локальная роль определяется по группам ОС, без env-оверрайдов.

    Правила:
    - root всегда admin
    - sudo: проверяем группы SUDO_USER
    - phantom-admin -> admin
    - phantom-editor -> editor
    - иначе viewer
    """
    if os.geteuid() == 0:
        sudo_user = os.getenv("SUDO_USER")
        if sudo_user:
            groups = _groups_for_user(sudo_user)
            if "phantom-admin" in groups:
                return "admin"
            if "phantom-editor" in groups:
                return "editor"
        return "admin"
    user = getpass.getuser()
    groups = _groups_for_user(user)
    if "phantom-admin" in groups:
        return "admin"
    if "phantom-editor" in groups:
        return "editor"
    return "viewer"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.command == "validate":
        try:
            get_config(args.config, reload=True)
            validate_config_for_daemon()
            print("OK: configuration is valid")
            return 0
        except Exception as exc:
            print(f"ERROR: configuration invalid: {exc}")
            return 1

    if args.command == "bootstrap":
        try:
            actions = bootstrap(config_path=args.config, plan=BootstrapPlan(), dry_run=bool(args.dry_run))
            for line in actions:
                print(line)
            return 0
        except Exception as exc:
            print(f"ERROR: bootstrap failed: {exc}")
            return 1

    if args.command == "prod-check":
        return run_prod_readiness_check(config_path=args.config, service_path=args.service, json_output=bool(args.json))

    if args.command == "run-once":
        orch = create_orchestrator(args.config)

        async def _run() -> None:
            await orch.start()
            print(json.dumps({"stats": orch.stats}, indent=2))
            await orch.stop()

        asyncio.run(_run())
        return 0

    if args.command == "mode":
        cfg = get_config(args.config)
        if args.mode_cmd == "get":
            orch_cfg = cfg.get("orchestrator", {})
            current_mode = str(orch_cfg.get("mode", "active")).lower()
            print(f"Current mode: {current_mode}")
            return 0
        if args.mode_cmd == "set":
            # Смена mode требует root-привилегий
            if os.geteuid() != 0:
                print("ERROR: mode change requires root privileges (sudo phantomctl mode set ...)")
                return 1
            import yaml as _yaml
            from pathlib import Path as _Path
            config_path = args.config
            p = _Path(config_path)
            if not p.exists():
                print(f"ERROR: config file not found: {config_path}")
                return 1
            try:
                with open(p, "r+", encoding="utf-8") as fh:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                    data = _yaml.safe_load(fh.read())
                    if not isinstance(data, dict):
                        data = {}
                    if "orchestrator" not in data or not isinstance(data["orchestrator"], dict):
                        data["orchestrator"] = {}
                    old_mode = data["orchestrator"].get("mode", "active")
                    new_mode = args.value
                    data["orchestrator"]["mode"] = new_mode
                    fh.seek(0)
                    fh.truncate()
                    fh.write(_yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
                print(f"Mode changed: {old_mode} -> {new_mode}")
                print("Restart the daemon or send SIGHUP to apply: kill -HUP $(pidof phantomd)")
                return 0
            except Exception as exc:
                print(f"ERROR: failed to change mode: {exc}")
                return 1
        parser.parse_args(["mode", "--help"])
        return 0

    if args.command == "templates":
        role = _resolve_local_role()
        cfg = get_config(args.config)
        user_root = str(cfg.get("paths", {}).get("user_templates_dir", "/etc/phantom/templates"))
        store = TemplateStore(user_root)

        if args.templates_cmd == "list":
            for item in store.list_templates():
                print(f"{item.name} {item.version} {item.path}")
            return 0

        if args.templates_cmd == "add":
            if role not in {"admin", "editor"}:
                print("ERROR: role does not allow template modifications")
                return 1
            try:
                path = store.add_template(args.source, args.name, args.version)
                print(f"stored: {path}")
                return 0
            except Exception as exc:
                print(f"ERROR: {exc}")
                return 1

        if args.templates_cmd == "activate":
            if role != "admin":
                print("ERROR: only admin can activate templates")
                return 1
            try:
                path = store.activate_template(args.name, args.version)
                print(f"activated: {path}")
                return 0
            except Exception as exc:
                print(f"ERROR: {exc}")
                return 1

        if args.templates_cmd == "show":
            try:
                info = store.get_template_info(args.name)
                print(f"Name:           {info.name}")
                print(f"Extension:      {info.extension}")
                print(f"Versions:       {', '.join(info.versions)}")
                print(f"Active version: {info.active_version or '(none)'}")
                print(f"Active path:    {info.active_path or '(none)'}")
                print(f"Total size:     {info.total_size_bytes} bytes")
                print(f"Created at:     {info.created_at or 'unknown'}")
                return 0
            except Exception as exc:
                print(f"ERROR: {exc}")
                return 1

        if args.templates_cmd == "remove":
            if role != "admin":
                print("ERROR: only admin can remove templates")
                return 1
            try:
                removed = store.remove_template(args.name, args.version)
                for path in removed:
                    print(f"removed: {path}")
                return 0
            except Exception as exc:
                print(f"ERROR: {exc}")
                return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Менеджер развёртывания ловушек.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import socket
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from phantom.core.traps import TrapEntry, TrapRegistry

from .generators import ContentGenerator
from .manifest import ManifestLoader, TrapTask

logger = logging.getLogger("phantom.factory.manager")


class TrapFactory:
    def __init__(
        self,
        config: Dict[str, Any],
        generator: Optional[ContentGenerator] = None,
        manifest_loader: Optional[ManifestLoader] = None,
    ) -> None:
        self.config = config
        self.paths = config.get("paths", {})
        self.traps_dir = str(self.paths.get("traps_dir", "/var/lib/phantom/traps"))
        self.templates_dir = str(self.paths.get("templates", "resources/templates"))
        self.user_templates_dir = str(self.paths.get("user_templates_dir", "/etc/phantom/templates"))
        self.registry_path = str(self.paths.get("trap_registry_file", Path(self.traps_dir) / "trap_registry.json"))

        self.stomp_config = config.get("time_stomping", {})
        self.generator = generator or ContentGenerator(stomp_config=self.stomp_config)
        manifest_path = str(self.paths.get("manifest", "config/traps_manifest.yaml"))
        self.manifest_loader = manifest_loader or ManifestLoader(manifest_path)
        self.templates_config = config.get("templates", {})

        self.base_context = self.generator.create_base_context()
        self.system_context = self._get_system_context()
        self.base_context.update(self.system_context)
        self.base_context.update(self._load_render_globals())

    def _get_system_context(self) -> Dict[str, Any]:
        try:
            user = os.getlogin()
        except OSError:
            user = getpass.getuser()
        try:
            host = socket.gethostname()
        except Exception:
            host = "unknown"
        return {"host": host, "user": user}

    def _template_roots(self) -> list[Path]:
        roots = [Path(self.templates_dir).resolve()]
        user_root = Path(self.user_templates_dir)
        if user_root.exists():
            roots.append(user_root.resolve())
        return roots

    def _load_render_globals(self) -> Dict[str, Any]:
        cfg = self.templates_config if isinstance(self.templates_config, dict) else {}
        merged: Dict[str, Any] = {}

        direct_globals = cfg.get("globals", cfg.get("global_vars", {}))
        if isinstance(direct_globals, dict):
            merged = self._deep_merge(merged, dict(direct_globals))

        datasets = cfg.get("datasets", [])
        if isinstance(datasets, list):
            for item in datasets:
                path = Path(str(item)).expanduser()
                if not path.is_absolute():
                    path = Path.cwd() / path
                loaded = self._load_dataset(path)
                if loaded:
                    merged = self._deep_merge(merged, loaded)

        return merged

    def _load_dataset(self, path: Path) -> Dict[str, Any]:
        if not path.exists() or not path.is_file():
            logger.warning("Template dataset not found: %s", path)
            return {}
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Template dataset read failed for %s: %s", path, exc)
            return {}

        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                data = json.loads(text)
            else:
                data = yaml.safe_load(text)
        except Exception as exc:
            logger.warning("Template dataset parse failed for %s: %s", path, exc)
            return {}
        if not isinstance(data, dict):
            logger.warning("Template dataset must be object mapping: %s", path)
            return {}
        return data

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(base)
        for key, value in override.items():
            if isinstance(merged.get(key), dict) and isinstance(value, dict):
                merged[key] = self._deep_merge(dict(merged[key]), value)
            else:
                merged[key] = value
        return merged

    def _resolve_template_path(self, template_rel: str) -> Path:
        rel = Path(template_rel)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"Unsafe template path: {template_rel}")

        candidates: list[Path] = []
        for root in self._template_roots():
            candidate = (root / rel).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.exists() and candidate.is_file():
                candidates.append(candidate)

            # Соглашение хранилища шаблонов: <name>/active -> vX.Y.Z.ext
            active_link = (root / rel / "active").resolve()
            try:
                active_link.relative_to(root)
            except ValueError:
                active_link = Path("/nonexistent")
            if active_link.exists() and active_link.is_file():
                candidates.append(active_link)

        if not candidates:
            raise FileNotFoundError(f"Template not found: {template_rel}")

        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        if len(candidates) > 1:
            logger.warning(
                "Template name conflict for %s; latest mtime wins: %s",
                template_rel,
                candidates[0],
            )
        return candidates[0]

    def _resolve_output_path(self, output_rel: str) -> Path:
        root = Path(self.traps_dir).resolve()
        rel = Path(output_rel)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"Unsafe output path: {output_rel}")
        out = (root / rel).resolve()
        out.relative_to(root)
        return out

    def deploy_traps(self) -> Dict[str, Any]:
        logger.info(
            "Trap deployment start. PID=%s context=%s@%s",
            os.getpid(),
            self.system_context["user"],
            self.system_context["host"],
        )

        Path(self.traps_dir).mkdir(parents=True, exist_ok=True)
        tasks = self.manifest_loader.load_tasks()
        if not tasks:
            logger.warning("No valid trap tasks in manifest")
            return {"deployed": 0, "total": 0, "registry": None}

        deployed_entries: list[TrapEntry] = []
        for task in tasks:
            if not self._deploy_task(task):
                continue

            output_path = str(self._resolve_output_path(task.output))
            deployed_entries.append(
                TrapEntry(
                    trap_id=task.trap_id,
                    output_path=output_path,
                    category=task.category,
                    priority=task.priority,
                    template=task.template,
                    fmt=task.fmt,
                )
            )

        registry = TrapRegistry.from_entries(self.traps_dir, deployed_entries)
        registry.export_json(self.registry_path)

        logger.info(
            "Trap deployment complete: %s/%s deployed",
            len(deployed_entries),
            len(tasks),
        )
        return {
            "deployed": len(deployed_entries),
            "total": len(tasks),
            "registry": self.registry_path,
        }

    def _deploy_task(self, task: TrapTask) -> bool:
        try:
            tpl_path = self._resolve_template_path(task.template)
            out_path = self._resolve_output_path(task.output)
        except Exception as exc:
            logger.error("Trap %s path resolution failed: %s", task.trap_id, exc)
            return False

        metadata = {
            "category": task.category,
            "priority": task.priority,
            "trap_id": task.trap_id,
        }

        try:
            if task.fmt == "text":
                trap_ctx = self.generator.create_trap_context(self.base_context)
                self.generator.create_text_trap(str(tpl_path), str(out_path), trap_ctx, metadata=metadata)
            else:
                self.generator.create_binary_trap(str(tpl_path), str(out_path), metadata=metadata)
            return True
        except Exception as exc:
            logger.error("Trap %s generation failed: %s", task.trap_id, exc)
            return False

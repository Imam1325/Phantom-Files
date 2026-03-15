"""
Загрузка и валидация манифеста ловушек.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger("phantom.factory.manifest")

ALLOWED_FORMATS = {"text", "binary"}
MAX_TEMPLATE_SIZE = 10 * 1024 * 1024


@dataclass(frozen=True)
class TrapTask:
    trap_id: str
    template: str
    output: str
    category: str
    fmt: str
    priority: str

    def to_dict(self) -> dict:
        return {
            "id": self.trap_id,
            "template": self.template,
            "output": self.output,
            "category": self.category,
            "format": self.fmt,
            "priority": self.priority,
        }


class ManifestLoader:
    def __init__(self, manifest_path: str) -> None:
        self.manifest_path = manifest_path

    def load(self) -> List[Dict[str, Any]]:
        tasks = self.load_tasks()
        return [task.to_dict() for task in tasks]

    def load_tasks(self) -> List[TrapTask]:
        manifest = Path(self.manifest_path)
        if not manifest.exists():
            logger.error("Manifest file not found: %s", manifest)
            return []

        try:
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            logger.error("Manifest YAML parse error: %s", exc)
            return []
        except OSError as exc:
            logger.error("Manifest read failed: %s", exc)
            return []

        if not isinstance(data, dict):
            logger.error("Manifest root must be a mapping")
            return []

        traps = data.get("traps", [])
        if not isinstance(traps, list):
            logger.error("Manifest 'traps' must be a list")
            return []

        valid: List[TrapTask] = []
        for item in traps:
            task = self._validate_task(item)
            if task is not None:
                valid.append(task)
        return valid

    def _validate_task(self, item: Any) -> TrapTask | None:
        if not isinstance(item, dict):
            logger.warning("Skipping invalid trap entry: expected mapping")
            return None

        trap_id = str(item.get("id", "")).strip()
        template = str(item.get("template", "")).strip()
        output = str(item.get("output", "")).strip()
        category = str(item.get("category", "generic")).strip() or "generic"
        fmt = str(item.get("format", "text")).strip().lower() or "text"
        priority = str(item.get("priority", "medium")).strip().lower() or "medium"

        if not trap_id or not template or not output:
            logger.warning("Skipping trap with missing id/template/output")
            return None
        if fmt not in ALLOWED_FORMATS:
            logger.warning("Skipping trap %s: unsupported format '%s'", trap_id, fmt)
            return None
        if output.startswith("/"):
            logger.warning("Skipping trap %s: output must be relative to traps_dir", trap_id)
            return None
        if ".." in Path(output).parts:
            logger.warning("Skipping trap %s: output path traversal blocked", trap_id)
            return None
        if ".." in Path(template).parts:
            logger.warning("Skipping trap %s: template path traversal blocked", trap_id)
            return None

        return TrapTask(
            trap_id=trap_id,
            template=template,
            output=output,
            category=category,
            fmt=fmt,
            priority=priority,
        )


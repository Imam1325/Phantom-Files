"""
Утилиты аудит-логирования для событий безопасности.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional

from phantom.core.state import Context, Decision, Event, ResponseResult
from phantom.core.config import get_path
from phantom.utils.fs import safe_mkdirs

logger = logging.getLogger("phantom.audit")


class AuditLogger:
    """
    Записывает аудит-записи в JSONL-файл в настроенном каталоге логов.
    """

    def __init__(self, filename: str = "audit.jsonl") -> None:
        try:
            base_dir = get_path("logs_dir")
        except Exception:
            base_dir = "/var/log/phantom"
            try:
                safe_mkdirs(base_dir)
            except Exception:
                base_dir = tempfile.mkdtemp(prefix="phantom_audit_")
                logger.warning(
                    "Cannot use /var/log/phantom for audit logs, using secure temp dir: %s",
                    base_dir,
                )
        safe_mkdirs(base_dir)
        self._path = Path(base_dir) / filename

    def log(
        self,
        *,
        event: Optional[Event] = None,
        context: Optional[Context] = None,
        decision: Optional[Decision] = None,
        result: Optional[ResponseResult] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        entry: dict[str, Any] = {}
        if event:
            entry["event"] = event.to_dict()
        if context:
            entry["context"] = context.to_dict()
        if decision:
            entry["decision"] = decision.to_dict()
        if result:
            entry["result"] = result.to_dict()
        if extra:
            entry["extra"] = dict(extra)

        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False))
                fh.write("\n")
        except Exception as exc:  # pragma: no cover - disk errors
            logger.error("Failed to write audit log: %s", exc)

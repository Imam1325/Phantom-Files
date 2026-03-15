"""
Утилиты Elastic Common Schema (ECS) для логирования Phantom.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict


def ecs_dict_from_record(record: logging.LogRecord) -> Dict[str, Any]:
    """
    Преобразование LogRecord в минимальный ECS-совместимый словарь.
    """
    timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
    return {
        "@timestamp": timestamp,
        "log.level": record.levelname.lower(),
        "log.logger": record.name,
        "message": record.getMessage(),
        "host": {"hostname": socket.gethostname()},
        "event": {"severity": record.levelno},
    }


class ECSFormatter(logging.Formatter):
    """Форматирует записи логов как ECS JSON-строки."""

    def format(self, record: logging.LogRecord) -> str:
        ecs = ecs_dict_from_record(record)
        if record.exc_info:
            ecs["error"] = {"message": self.formatException(record.exc_info)}
        import json

        return json.dumps(ecs, ensure_ascii=False)


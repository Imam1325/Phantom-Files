from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).isoformat()


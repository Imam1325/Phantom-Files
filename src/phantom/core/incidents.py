"""
Хранилище инцидентов с агрегацией и дедупликацией.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from phantom.core.state import Event, generate_incident_id


@dataclass
class IncidentRecord:
    incident_id: str
    trap_path: str
    pid: Optional[int]
    first_seen: datetime
    last_seen: datetime
    event_count: int = 1
    last_event_id: Optional[str] = None
    status: str = "open"

    def touch(self, event: Event) -> None:
        self.last_seen = event.timestamp
        self.event_count += 1
        self.last_event_id = event.event_id

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "trap_path": self.trap_path,
            "pid": self.pid,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "last_event_id": self.last_event_id,
            "status": self.status,
        }


class IncidentStore:
    """
    Группирует всплески событий для одной ловушки и PID в единый инцидент.
    """

    def __init__(self, dedup_window_seconds: float = 2.0, max_records: int = 10000) -> None:
        self.dedup_window = float(dedup_window_seconds)
        self._max_records = int(max_records)
        self._records: Dict[Tuple[str, Optional[int]], IncidentRecord] = {}
        self._archived: deque[IncidentRecord] = deque(maxlen=self._max_records)
        self._lock = asyncio.Lock()

    async def upsert(self, event: Event) -> IncidentRecord:
        key = (event.target_path, event.process_pid)
        now = event.timestamp
        async with self._lock:
            record = self._records.get(key)
            if record is not None:
                age = (now - record.last_seen).total_seconds()
                if age <= self.dedup_window:
                    record.touch(event)
                    return record
                record.status = "closed"
                self._archived.append(record)

            if len(self._records) >= self._max_records:
                self._evict_oldest()

            new_record = IncidentRecord(
                incident_id=generate_incident_id(),
                trap_path=event.target_path,
                pid=event.process_pid,
                first_seen=now,
                last_seen=now,
                event_count=1,
                last_event_id=event.event_id,
            )
            self._records[key] = new_record
            return new_record

    async def all_open(self) -> list[IncidentRecord]:
        async with self._lock:
            return list(self._records.values())

    def _evict_oldest(self) -> None:
        oldest_key: Optional[Tuple[str, Optional[int]]] = None
        oldest_ts = datetime.now(timezone.utc)
        for key, record in self._records.items():
            if record.last_seen <= oldest_ts:
                oldest_ts = record.last_seen
                oldest_key = key
        if oldest_key is not None:
            del self._records[oldest_key]

"""
Реестр ловушек для обнаружения несанкционированного доступа.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

logger = logging.getLogger("phantom.traps")


@dataclass(frozen=True)
class TrapEntry:
    trap_id: str
    output_path: str
    category: str
    priority: str
    template: str
    fmt: str

    def to_dict(self) -> dict:
        return {
            "trap_id": self.trap_id,
            "output_path": self.output_path,
            "category": self.category,
            "priority": self.priority,
            "template": self.template,
            "format": self.fmt,
        }


class TrapRegistry:
    def __init__(self, traps_root: str) -> None:
        self._root = Path(traps_root).resolve()
        self._by_path: Dict[str, TrapEntry] = {}

    @property
    def root(self) -> str:
        return str(self._root)

    def register(self, entry: TrapEntry) -> None:
        normalized = self.normalize(entry.output_path)
        self._by_path[normalized] = TrapEntry(
            trap_id=entry.trap_id,
            output_path=normalized,
            category=entry.category,
            priority=entry.priority,
            template=entry.template,
            fmt=entry.fmt,
        )

    def lookup(self, path: str) -> Optional[TrapEntry]:
        try:
            return self._by_path.get(self.normalize(path))
        except ValueError:
            logger.warning("Path traversal attempt blocked: %s", path)
            return None

    def contains(self, path: str) -> bool:
        return self.lookup(path) is not None

    def entries(self) -> list[TrapEntry]:
        return list(self._by_path.values())

    def normalize(self, path: str) -> str:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self._root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError as exc:
            raise ValueError(f"Path escapes traps root: {path}") from exc
        return str(resolved)

    def export_json(self, target_path: str) -> None:
        payload = {
            "root": str(self._root),
            "traps": [entry.to_dict() for entry in self.entries()],
        }
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def reload_from_json(self, path: str) -> None:
        fresh = self.from_json(path, expected_root=str(self._root))
        self._root = Path(fresh.root).resolve()
        self._by_path = {entry.output_path: entry for entry in fresh.entries()}

    @classmethod
    def from_entries(cls, traps_root: str, entries: Iterable[TrapEntry]) -> "TrapRegistry":
        reg = cls(traps_root=traps_root)
        for entry in entries:
            reg.register(entry)
        return reg

    @classmethod
    def from_json(cls, path: str, expected_root: str | None = None) -> "TrapRegistry":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        root = Path(str(data["root"])).resolve()
        if expected_root is not None:
            expected = Path(expected_root).resolve()
            if root != expected:
                raise ValueError(f"Trap registry root mismatch: {root} != {expected}")
            root = expected
        reg = cls(traps_root=str(root))
        for item in data.get("traps", []):
            reg.register(
                TrapEntry(
                    trap_id=item["trap_id"],
                    output_path=item["output_path"],
                    category=item.get("category", "unknown"),
                    priority=item.get("priority", "medium"),
                    template=item.get("template", ""),
                    fmt=item.get("format", "text"),
                )
            )
        return reg

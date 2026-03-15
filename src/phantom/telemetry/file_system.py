"""
Filesystem telemetry collector.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from phantom.core.config import get_config
from phantom.core.state import FileInfo
from phantom.core.traps import TrapRegistry


class FileSystemCollector:
    def __init__(self) -> None:
        self._registry: TrapRegistry | None = None
        self._registry_path: Path | None = None
        self._registry_mtime: float | None = None
        self._traps_root: str | None = None
        try:
            cfg = get_config()
            reg_path = cfg.get("paths", {}).get("trap_registry_file")
            traps_root = cfg.get("paths", {}).get("traps_dir")
            if traps_root:
                self._traps_root = str(traps_root)
            if reg_path:
                self._registry_path = Path(str(reg_path))
                self._refresh_registry()
        except Exception:
            self._registry = None

    async def collect(self, path: str) -> Optional[FileInfo]:
        return await asyncio.to_thread(self._collect_sync, path)

    def _collect_sync(self, path: str) -> Optional[FileInfo]:
        try:
            self._refresh_registry()
            resolved = Path(path).resolve()
            st = os.stat(resolved, follow_symlinks=False)
        except OSError:
            return None

        trap_id = None
        trap_type = None
        if self._registry:
            trap = self._registry.lookup(str(resolved))
            if trap:
                trap_id = trap.trap_id
                trap_type = trap.category

        return FileInfo(
            path=str(resolved),
            inode=getattr(st, "st_ino", None),
            size=getattr(st, "st_size", None),
            owner_uid=getattr(st, "st_uid", None),
            owner_gid=getattr(st, "st_gid", None),
            mode=getattr(st, "st_mode", None),
            mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
            atime=datetime.fromtimestamp(st.st_atime, tz=timezone.utc),
            ctime=datetime.fromtimestamp(st.st_ctime, tz=timezone.utc),
            trap_id=trap_id,
            trap_type=trap_type,
        )

    def _refresh_registry(self) -> None:
        if not self._registry_path or not self._registry_path.exists():
            self._registry = None
            self._registry_mtime = None
            return
        try:
            mtime = self._registry_path.stat().st_mtime
            if self._registry is None or mtime != self._registry_mtime:
                self._registry = TrapRegistry.from_json(
                    str(self._registry_path),
                    expected_root=self._traps_root,
                )
                self._registry_mtime = mtime
        except Exception:
            self._registry = None

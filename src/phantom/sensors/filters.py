"""
Утилиты фильтрации сенсоров.
"""

from __future__ import annotations

import fnmatch
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Optional


class DebounceFilter:
    def __init__(self, window_seconds: float = 1.0, max_keys: int = 50000) -> None:
        self.window = float(window_seconds)
        self._seen: Dict[str, float] = {}
        self._max_keys = max_keys
        self._cleanup_counter = 0

    def allow(self, key: str) -> bool:
        now = time.time()
        last = self._seen.get(key, 0.0)
        if now - last < self.window:
            return False
        self._seen[key] = now
        self._cleanup_counter += 1
        if self._cleanup_counter >= 1000:
            self._evict_expired(now)
            self._cleanup_counter = 0
        return True

    def _evict_expired(self, now: float) -> None:
        """Удаление устаревших записей для предотвращения утечки памяти."""
        expired = [k for k, ts in self._seen.items() if now - ts > self.window * 10]
        for k in expired:
            del self._seen[k]
        if len(self._seen) > self._max_keys:
            # Аварийная очистка: оставляем только самые свежие
            sorted_keys = sorted(self._seen, key=self._seen.get, reverse=True)
            for k in sorted_keys[self._max_keys:]:
                del self._seen[k]


def path_match(path: str, patterns: Optional[Iterable[str]]) -> bool:
    if not patterns:
        return False
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
    return False


_LSOF_LOCK = threading.Lock()
_LAST_LSOF_TS = 0.0


def resolve_pid_for_path(
    path: str,
    timeout_seconds: float = 0.3,
    min_interval_seconds: float = 0.0,
) -> tuple[int | None, str | None]:
    """
    Приблизительное определение PID для деградированного режима inotify.
    """
    global _LAST_LSOF_TS
    if min_interval_seconds > 0:
        now = time.time()
        with _LSOF_LOCK:
            if now - _LAST_LSOF_TS < min_interval_seconds:
                return None, None
            _LAST_LSOF_TS = now
    try:
        proc = subprocess.run(
            ["lsof", "-n", "-t", "--", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except Exception:
        return None, None

    if proc.returncode != 0 or not proc.stdout.strip():
        return None, None

    first_line = proc.stdout.splitlines()[0].strip()
    if not first_line.isdigit():
        return None, None
    pid = int(first_line)

    name: str | None = None
    try:
        name = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        name = None
    return pid, name

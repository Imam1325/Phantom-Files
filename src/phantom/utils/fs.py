from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import List, Optional


def safe_mkdirs(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def atomic_write(path: str, data: str, *, encoding: str = "utf-8") -> None:
    target = Path(path)
    tmp_dir = target.parent if target.parent.exists() else Path(".")
    fd: int | None = None
    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(tmp_dir))
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except Exception:
                pass
        os.replace(tmp_path, path)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def read_text_safe(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return default


def list_files(directory: str, pattern: Optional[str] = None) -> List[str]:
    files: List[str] = []
    base = Path(directory)
    if not base.exists():
        return files
    for item in base.iterdir():
        if item.is_file():
            if pattern and not item.match(pattern):
                continue
            files.append(str(item))
    return files

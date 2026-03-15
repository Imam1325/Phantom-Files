"""
Хранилище пользовательских шаблонов с версионированием.

Позволяет операторам добавлять собственные Jinja2-шаблоны ловушек
с поддержкой SemVer-версионирования, активации конкретной версии
и автоматическим удалением устаревших версий.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from shutil import which
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

logger = logging.getLogger("phantom.factory.templates")

SEMVER_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# Запрещённые конструкции в текстовых шаблонах (Jinja2 sandbox ловит не всё)
_FORBIDDEN_PATTERNS = re.compile(
    r"os\.system|subprocess|__import__|eval\s*\(|exec\s*\(|"
    r"importlib|__builtins__|__class__|__subclasses__|"
    r"popen|commands\.get|pty\.spawn",
    re.IGNORECASE,
)
TEXT_EXTENSIONS = frozenset({".j2", ".txt", ".env", ".sql", ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf", ".sh", ".py"})
BINARY_EXTENSIONS = frozenset({".docx", ".xlsx", ".pdf", ".pptx", ".zip"})


@dataclass(frozen=True)
class TemplateVersion:
    """Одна версия пользовательского шаблона."""
    name: str
    version: str
    path: str


@dataclass(frozen=True)
class TemplateInfo:
    """Подробная информация о шаблоне."""
    name: str
    versions: list[str]
    active_version: str | None
    active_path: str | None
    total_size_bytes: int
    created_at: str | None
    extension: str


class TemplateStore:
    """
    Хранилище пользовательских шаблонов.

    Структура каталога:
        <root>/
          <name>/
            v1.0.0.j2
            v1.1.0.j2
            active -> v1.1.0.j2  (symlink)
    """

    def __init__(self, root: str, max_versions: int = 5) -> None:
        self.root = Path(root)
        self.max_versions = max_versions
        # Не создаём каталог здесь: операции чтения (например list) не должны
        # пытаться создавать системные пути типа /etc/phantom/templates и падать без root.

    def list_templates(self) -> list[TemplateVersion]:
        """Список всех версий всех шаблонов."""
        if not self.root.exists():
            return []
        result: list[TemplateVersion] = []
        for template_dir in sorted(self.root.glob("*")):
            if not template_dir.is_dir():
                continue
            versions = sorted(self._version_files(template_dir), key=self._version_sort_key, reverse=True)
            for p in versions:
                result.append(TemplateVersion(name=template_dir.name, version=p.stem, path=str(p)))
        return result

    def get_template_info(self, name: str) -> TemplateInfo:
        """Подробная информация о шаблоне: версии, активная версия, размер."""
        if not NAME_RE.match(name):
            raise ValueError("Unsafe template name")
        template_dir = self.root / name
        if not template_dir.exists():
            raise FileNotFoundError(f"Template not found: {name}")

        version_files = sorted(self._version_files(template_dir), key=self._version_sort_key, reverse=True)
        versions = [f.stem for f in version_files]
        total_size = sum(f.stat().st_size for f in version_files)
        ext = version_files[0].suffix if version_files else ""

        # Определяем активную версию
        active_link = template_dir / "active"
        active_version = None
        active_path = None
        if active_link.is_symlink() or active_link.exists():
            try:
                target = active_link.resolve()
                if target.exists():
                    active_version = target.stem
                    active_path = str(target)
            except Exception:
                pass

        # Время создания (по старейшей версии)
        created_at = None
        if version_files:
            oldest = min(version_files, key=lambda f: f.stat().st_ctime)
            ts = oldest.stat().st_ctime
            created_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        return TemplateInfo(
            name=name,
            versions=versions,
            active_version=active_version,
            active_path=active_path,
            total_size_bytes=total_size,
            created_at=created_at,
            extension=ext,
        )

    def add_template(self, source: str, name: str, version: str) -> str:
        """
        Добавление нового шаблона (или новой версии существующего).

        Валидация:
        - SemVer формат версии (vMAJOR.MINOR.PATCH)
        - Безопасное имя (только [A-Za-z0-9._-])
        - Размер файла <= 10 МБ
        - Jinja2 sandbox парсинг для текстовых шаблонов
        - Проверка на запрещённые конструкции (os.system, eval, exec, ...)
        - Антивирусная проверка (clamscan) для бинарных шаблонов
        """
        if not SEMVER_RE.match(version):
            raise ValueError("Version must follow vMAJOR.MINOR.PATCH")
        src = Path(source)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(source)
        if src.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Template exceeds 10MB limit")
        if not NAME_RE.match(name):
            raise ValueError("Unsafe template name")

        self._validate_template_file(src)

        self.root.mkdir(parents=True, exist_ok=True)
        target_dir = self.root / name
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / f"{version}{src.suffix}"

        # Предупреждение при перезаписи существующей версии
        if target_file.exists():
            logger.warning("Overwriting existing template version: %s", target_file)

        shutil.copy2(src, target_file)
        os.chmod(target_file, 0o640)
        self._prune_old_versions(target_dir)
        logger.info("Template stored: %s", target_file)
        return str(target_file)

    def remove_template(self, name: str, version: str | None = None) -> list[str]:
        """
        Удаление шаблона.

        Если version указана — удаляется конкретная версия.
        Если version=None — удаляется весь шаблон со всеми версиями.

        Возвращает список удалённых путей.
        """
        if not NAME_RE.match(name):
            raise ValueError("Unsafe template name")
        template_dir = self.root / name
        if not template_dir.exists():
            raise FileNotFoundError(f"Template not found: {name}")

        removed: list[str] = []

        if version is not None:
            # Удаление конкретной версии
            if not SEMVER_RE.match(version):
                raise ValueError("Version must follow vMAJOR.MINOR.PATCH")
            candidates = list(template_dir.glob(f"{version}.*"))
            if not candidates:
                raise FileNotFoundError(f"Version not found: {name}:{version}")
            for f in candidates:
                removed.append(str(f))
                f.unlink()
            # Если удалённая версия была active — снимаем symlink
            active_link = template_dir / "active"
            if active_link.is_symlink():
                try:
                    target_name = os.readlink(str(active_link))
                    if any(Path(target_name).stem == version for _ in [1]):
                        active_link.unlink()
                        logger.info("Active symlink removed (deleted version was active)")
                except Exception:
                    pass
            # Если не осталось версий — удаляем каталог
            remaining = self._version_files(template_dir)
            if not remaining:
                active_link = template_dir / "active"
                if active_link.is_symlink():
                    active_link.unlink(missing_ok=True)
                template_dir.rmdir()
                removed.append(str(template_dir))
        else:
            # Удаление всего шаблона
            for f in template_dir.iterdir():
                removed.append(str(f))
            shutil.rmtree(template_dir)
            removed.append(str(template_dir))

        logger.info("Template removed: %s (files: %d)", name, len(removed))
        return removed

    def _validate_template_file(self, src: Path) -> None:
        """Валидация файла шаблона перед добавлением в хранилище."""
        suffix = src.suffix.lower()

        if suffix in TEXT_EXTENSIONS:
            text = src.read_text(encoding="utf-8")
            # Проверка на запрещённые конструкции
            match = _FORBIDDEN_PATTERNS.search(text)
            if match:
                raise ValueError(f"Forbidden pattern detected in template: '{match.group()}'")
            # Jinja2 sandbox парсинг — проверяет синтаксис
            env = SandboxedEnvironment(undefined=StrictUndefined)
            env.parse(text)
            return

        if suffix in BINARY_EXTENSIONS:
            scanner = which("clamscan")
            if scanner:
                proc = subprocess.run(
                    [scanner, "--no-summary", str(src)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.returncode != 0:
                    raise ValueError(f"Antivirus check failed: {proc.stdout or proc.stderr}")
            return

        raise ValueError(f"Unsupported template extension: {suffix}")

    def _prune_old_versions(self, template_dir: Path) -> None:
        """Удаление самых старых версий, если их больше max_versions."""
        files = sorted(self._version_files(template_dir), key=self._version_sort_key, reverse=True)
        active_link = template_dir / "active"
        active_target: Path | None = None
        if active_link.is_symlink():
            try:
                active_target = active_link.resolve()
            except Exception:
                active_target = None
        removed = 0
        for old in reversed(files):
            if active_target is not None:
                try:
                    if old.resolve() == active_target:
                        continue
                except Exception:
                    pass
            if len(files) - removed <= self.max_versions:
                break
            old.unlink(missing_ok=True)
            removed += 1
            logger.debug("Pruned old template version: %s", old)

    def activate_template(self, name: str, version: str) -> str:
        """Активация конкретной версии шаблона (создаёт symlink 'active')."""
        if not SEMVER_RE.match(version):
            raise ValueError("Version must follow vMAJOR.MINOR.PATCH")
        template_dir = self.root / name
        if not template_dir.exists():
            raise FileNotFoundError(name)
        candidates = list(template_dir.glob(f"{version}.*"))
        if not candidates:
            raise FileNotFoundError(f"{name}:{version}")
        target = candidates[0]
        active_link = template_dir / "active"
        fd, tmp_name = tempfile.mkstemp(prefix=".active.", dir=str(template_dir))
        os.close(fd)
        os.unlink(tmp_name)
        tmp_link = Path(tmp_name)
        tmp_link.symlink_to(target.name)
        os.replace(tmp_link, active_link)
        logger.info("Template activated: %s -> %s", name, version)
        return str(active_link)

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Сериализация для API (/api/v1/templates)."""
        result: list[dict[str, Any]] = []
        if not self.root.exists():
            return result
        for template_dir in sorted(self.root.glob("*")):
            if not template_dir.is_dir():
                continue
            version_files = sorted(self._version_files(template_dir), key=self._version_sort_key, reverse=True)
            versions = [f.stem for f in version_files]
            active_link = template_dir / "active"
            active_version = None
            if active_link.is_symlink():
                try:
                    active_version = active_link.resolve().stem
                except Exception:
                    pass
            result.append({
                "name": template_dir.name,
                "versions": versions,
                "active_version": active_version,
                "extension": version_files[0].suffix if version_files else "",
            })
        return result

    def _version_files(self, template_dir: Path) -> list[Path]:
        result: list[Path] = []
        for candidate in template_dir.iterdir():
            if not candidate.is_file():
                continue
            if self._parse_semver(candidate.stem) is None:
                continue
            result.append(candidate)
        return result

    def _version_sort_key(self, path: Path) -> tuple[int, int, int, str]:
        parsed = self._parse_semver(path.stem)
        if parsed is None:
            return (0, 0, 0, path.name)
        return (parsed[0], parsed[1], parsed[2], path.name)

    def _parse_semver(self, version: str) -> tuple[int, int, int] | None:
        match = SEMVER_RE.match(version)
        if not match:
            return None
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))

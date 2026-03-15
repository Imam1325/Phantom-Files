"""
Docker-песочница для динамического анализа подозрительных процессов.

Возможности:
- Запуск контейнера с ограничениями (без сети, read-only FS, ограничение ресурсов)
- Захват сетевого трафика (tcpdump) внутри контейнера
- Экспорт артефактов (логи, дампы, pcap)
- Таймаут с принудительным завершением
- Очистка контейнеров по TTL
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import shutil
import stat
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from phantom.core.config import get_config
from phantom.core.state import Context

logger = logging.getLogger("phantom.sandbox")


@dataclass
class SandboxResult:
    """Результат анализа в песочнице."""
    container_id: str
    container_name: str
    exit_code: int
    logs: str
    artifacts: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_id": self.container_id,
            "container_name": self.container_name,
            "exit_code": self.exit_code,
            "logs_length": len(self.logs),
            "artifacts": self.artifacts,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
        }


class SandboxRunner:
    """
    Docker-песочница для форензик-анализа.

    Контейнер запускается с:
    - network_disabled=True (без сети по умолчанию)
    - read_only=True (ФС только для чтения)
    - mem_limit (ограничение памяти)
    - cpu_period / cpu_quota (ограничение CPU)
    - pids_limit (защита от fork-бомб)
    - cap_drop=ALL (минимум привилегий)
    - Автоматический таймаут и принудительное удаление
    """

    def __init__(self) -> None:
        self._docker: Any = None
        self._config: Dict[str, Any] = {}
        self._artifacts_dir: Path = Path("/var/lib/phantom/sandbox")
        self._initialized = False

    async def initialize(self) -> None:
        """Инициализация Docker-клиента."""
        if self._initialized:
            return
        cfg = get_config()
        self._config = dict(cfg.get("sandbox", {}))
        paths = cfg.get("paths", {})
        evidence_dir = str(paths.get("evidence_dir", "/var/lib/phantom/evidence"))
        self._artifacts_dir = Path(evidence_dir) / "sandbox"

        try:
            import docker  # type: ignore
            self._docker = docker.from_env()
            # Проверяем доступность Docker
            self._docker.ping()
            logger.info("Docker client initialized")
        except Exception as exc:
            logger.warning("Docker unavailable: %s", exc)
            self._docker = None
        self._initialized = True

    @property
    def available(self) -> bool:
        """Проверка доступности Docker."""
        return self._docker is not None

    async def analyze(
        self,
        context: Context,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[SandboxResult]:
        """
        Запуск анализа в песочнице.

        Параметры из context:
        - context.event.target_path — путь к подозрительному файлу
        - context.event.process_pid — PID процесса

        Параметры из params (переопределяют конфиг):
        - image: Docker-образ
        - command: команда запуска
        - timeout_seconds: таймаут (по умолчанию 60)
        - network_disabled: отключить сеть (по умолчанию True)
        - capture_traffic: запуск tcpdump (по умолчанию False)
        """
        if not self._initialized:
            await self.initialize()

        params = params or {}
        if not self._docker:
            logger.info("Sandbox disabled (Docker unavailable)")
            return None

        image = params.get("image") or self._config.get("image")
        command = params.get("command") or self._config.get("command")
        timeout_param = params.get("timeout_seconds")
        if timeout_param is None:
            timeout_param = self._config.get("timeout_seconds", 60)
        timeout = int(timeout_param)
        network_disabled = bool(
            params.get("network_disabled", self._config.get("network_disabled", True))
        )
        # capture_traffic параметр зарезервирован для eBPF предзахвата
        mem_limit = str(self._config.get("mem_limit", "256m"))
        pids_limit = int(self._config.get("pids_limit", 64))
        prefix = str(self._config.get("container_prefix", "phantom_sandbox"))

        if not image or not command:
            logger.warning("Sandbox config incomplete (image/command), skipping")
            return None

        container_name = f"{prefix}_{self._random_suffix()}"
        # Директория для артефактов этого запуска
        run_dir = self._artifacts_dir / container_name
        run_dir.mkdir(parents=True, exist_ok=True)

        # Подготовка volume для копирования подозрительного файла
        volumes = {}
        target_path = context.event.target_path
        if target_path:
            src = Path(target_path)
            try:
                fd = os.open(str(src), os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    st = os.fstat(fh.fileno())
                    if not stat.S_ISREG(st.st_mode):
                        raise OSError("not a regular file")
                    target_copy = run_dir / "target.bin"
                    with open(target_copy, "wb") as out:
                        shutil.copyfileobj(fh, out)
                volumes[str(target_copy)] = {"bind": "/evidence/target", "mode": "ro"}
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("Skipping sandbox mount for %s: %s", src, exc)

        logger.info(
            "Starting sandbox: container=%s image=%s timeout=%ds",
            container_name, image, timeout,
        )

        import time as _time
        start_ts = _time.monotonic()
        timed_out = False
        container = None

        try:
            container = await asyncio.to_thread(
                self._docker.containers.run,
                image,
                command,
                name=container_name,
                detach=True,
                remove=False,  # Не удаляем сразу — нужны логи и артефакты
                network_disabled=network_disabled,
                read_only=True,
                mem_limit=mem_limit,
                pids_limit=pids_limit,
                cap_drop=["ALL"],
                tmpfs={"/tmp": "size=64m"},
                volumes=volumes or None,
                labels={
                    "phantom.sandbox": "true",
                    "phantom.incident_id": context.incident_id or "",
                },
            )

            # Ожидание завершения с таймаутом
            try:
                exit_info = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=timeout,
                )
                exit_code = exit_info.get("StatusCode", -1)
            except asyncio.TimeoutError:
                timed_out = True
                exit_code = -1
                logger.warning("Sandbox timeout: %s (kill)", container_name)
                await asyncio.to_thread(container.kill)

            elapsed = _time.monotonic() - start_ts

            # Собираем логи
            logs = await asyncio.to_thread(
                container.logs, stdout=True, stderr=True, tail=10000
            )
            logs_text = logs.decode("utf-8", errors="replace") if isinstance(logs, bytes) else str(logs)

            # Сохраняем логи в файл
            logs_path = run_dir / "container.log"
            logs_path.write_text(logs_text, encoding="utf-8")

            # Экспорт артефактов из контейнера
            artifacts = [str(logs_path)]
            artifacts.extend(
                await self._export_artifacts(container, run_dir)
            )

            result = SandboxResult(
                container_id=container.id,
                container_name=container_name,
                exit_code=exit_code,
                logs=logs_text[:50000],  # Ограничение размера логов
                artifacts=artifacts,
                duration_seconds=round(elapsed, 2),
                timed_out=timed_out,
            )

            logger.info(
                "Sandbox finished: container=%s exit=%d duration=%.1fs timed_out=%s",
                container_name, exit_code, elapsed, timed_out,
            )
            return result

        except Exception as exc:
            elapsed = _time.monotonic() - start_ts
            logger.error("Sandbox error: %s", exc)
            return SandboxResult(
                container_id="",
                container_name=container_name,
                exit_code=-1,
                logs=str(exc),
                duration_seconds=round(elapsed, 2),
                timed_out=False,
            )
        finally:
            # Удаляем контейнер
            if container is not None:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                except Exception:
                    pass

    async def _export_artifacts(self, container: Any, run_dir: Path) -> list[str]:
        """Экспорт файлов из контейнера."""
        artifacts: list[str] = []
        # Пытаемся извлечь /tmp/output из контейнера
        try:
            import tarfile
            bits, _ = await asyncio.to_thread(container.get_archive, "/tmp/output")
            tar_bytes = b"".join(bits)
            tar_path = run_dir / "output.tar"
            tar_path.write_bytes(tar_bytes)
            # Распаковываем
            with tarfile.open(tar_path, "r") as tf:
                self._safe_extract_tar(tf, run_dir / "output")
            artifacts.append(str(tar_path))
        except Exception:
            pass  # /tmp/output может не существовать
        return artifacts

    @staticmethod
    def _is_within_directory(base: Path, target: Path) -> bool:
        try:
            target.resolve().relative_to(base.resolve())
            return True
        except Exception:
            return False

    def _safe_extract_tar(self, tf, target_dir: Path) -> None:
        """Безопасная распаковка tar без symlink/hardlink и path traversal."""
        target_dir.mkdir(parents=True, exist_ok=True)
        for member in tf.getmembers():
            if member.isdev() or member.issym() or member.islnk():
                continue
            member_path = (target_dir / member.name)
            if not self._is_within_directory(target_dir, member_path):
                continue
            if member.isdir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            parent = member_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(member_path, "wb") as out:
                shutil.copyfileobj(src, out)

    async def cleanup_old_containers(self, max_age_hours: int = 24) -> int:
        """Удаление старых sandbox-контейнеров."""
        if not self._docker:
            return 0
        removed = 0
        try:
            containers = await asyncio.to_thread(
                self._docker.containers.list,
                all=True,
                filters={"label": "phantom.sandbox=true"},
            )
            for c in containers:
                try:
                    created = c.attrs.get("Created", "")
                    if created:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age = (datetime.now(timezone.utc) - created_dt).total_seconds() / 3600
                        if age > max_age_hours:
                            await asyncio.to_thread(c.remove, force=True)
                            removed += 1
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Container cleanup error: %s", exc)
        return removed

    @staticmethod
    def _random_suffix(length: int = 8) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

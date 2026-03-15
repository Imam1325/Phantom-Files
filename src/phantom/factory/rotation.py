"""
Ротация ловушек по времени.

TrapRotator периодически обновляет подмножество ловушек:
- Выбирает ловушки для обновления по алгоритму round-robin
- Генерирует новое содержимое (рандомизация)
- Обновляет метаданные (timestamp, хэш)
- Уведомляет SensorManager об изменениях
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from phantom.core.config import get_config
from phantom.core.traps import TrapRegistry
from phantom.factory.metadata import stomp_timestamp

logger = logging.getLogger("phantom.factory.rotation")


class TrapRotator:
    """
    Ротация ловушек с настраиваемым интервалом.

    Параметры конфигурации (rotation секция):
    - enabled: bool (по умолчанию True)
    - interval_seconds: int (по умолчанию 3600 — 1 час)
    - batch_size: int (по умолчанию 5 — обновлять 5 ловушек за раз)
    - min_age_seconds: int (по умолчанию 1800 — не обновлять младше 30 минут)
    """

    def __init__(
        self,
        trap_registry: TrapRegistry,
        deploy_callback: Callable[[str], None],
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        cfg = config or dict(get_config().get("rotation", {}))
        self._registry = trap_registry
        self._deploy_callback = deploy_callback
        self._enabled = bool(cfg.get("enabled", True))
        self._interval = max(60, int(cfg.get("interval_seconds", 3600)))
        self._batch_size = max(1, int(cfg.get("batch_size", 5)))
        self._min_age = int(cfg.get("min_age_seconds", 1800))
        raw_cfg = get_config()
        self._stomp_config = dict(raw_cfg.get("time_stomping", {})) if hasattr(raw_cfg, "get") else {}
        self._task: Optional[asyncio.Task] = None
        self._running = False
        # Индекс round-robin
        self._rotation_index = 0

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Запуск фонового цикла ротации."""
        if not self._enabled:
            logger.info("Trap rotation disabled")
            return
        if self._running:
            return
        self._running = True
        if loop is not None:
            _loop = loop
        else:
            try:
                _loop = asyncio.get_running_loop()
            except RuntimeError as exc:
                raise RuntimeError("TrapRotator.start requires a running event loop") from exc
        self._task = _loop.create_task(self._rotation_loop())
        logger.info(
            "Trap rotation started: interval=%ds batch=%d",
            self._interval, self._batch_size,
        )

    def stop(self) -> None:
        """Остановка ротации."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _rotation_loop(self) -> None:
        """Основной цикл ротации."""
        while self._running:
            try:
                await asyncio.sleep(self._interval)
                if not self._running:
                    break
                await self.rotate_batch()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Rotation error: %s", exc)

    async def rotate_batch(self) -> int:
        """
        Ротация одного батча ловушек.

        Возвращает количество обновлённых ловушек.
        """
        entries = self._registry.entries()
        if not entries:
            return 0

        now = time.time()
        # Фильтруем по минимальному возрасту
        eligible = []
        for entry in entries:
            path = Path(entry.output_path)
            if not path.exists():
                continue
            try:
                mtime = path.stat().st_mtime
                age = now - mtime
                if age >= self._min_age:
                    eligible.append(entry)
            except OSError:
                continue

        if not eligible:
            return 0

        # Round-robin выбор
        batch = []
        for i in range(self._batch_size):
            idx = (self._rotation_index + i) % len(eligible)
            batch.append(eligible[idx])
        self._rotation_index = (self._rotation_index + self._batch_size) % max(1, len(eligible))

        rotated = 0
        for entry in batch:
            try:
                await asyncio.to_thread(self._rotate_single, entry)
                rotated += 1
            except Exception as exc:
                logger.warning("Failed to rotate trap %s: %s", entry.output_path, exc)

        if rotated > 0:
            logger.info("Rotated %d/%d traps", rotated, len(batch))
            # Уведомление callback для перечитки сенсорами
            try:
                self._deploy_callback(f"rotated:{rotated}")
            except Exception:
                pass

        return rotated

    def _rotate_single(self, entry: Any) -> None:
        """Обновление одной ловушки: перезапись содержимого + метаданные."""
        path = Path(entry.output_path)
        if not path.exists():
            return

        # Читаем текущее содержимое
        try:
            current = path.read_bytes()
        except OSError:
            return

        # Генерируем новое содержимое с минимальными изменениями
        # (добавляем/меняем whitespace, чтобы изменился хэш)
        new_content = self._mutate_content(current)

        # Атомарная запись через tmp файл
        tmp_path = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
            tmp_path = Path(tmp_name)
            with os.fdopen(fd, "wb") as fh:
                fh.write(new_content)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except Exception:
                    pass
                # Копируем метаданные (права, владелец)
                stat = path.stat()
                try:
                    os.fchmod(fh.fileno(), stat.st_mode)
                except Exception:
                    pass
                try:
                    os.fchown(fh.fileno(), stat.st_uid, stat.st_gid)
                except OSError:
                    pass
            # Атомарная замена
            os.replace(str(tmp_path), path)
            # Возвращаем антифорензик-метки времени после ротации.
            stomp_timestamp(str(path), config=self._stomp_config)
        except Exception:
            # Удаляем tmp при ошибке
            try:
                if tmp_path is not None:
                    tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @staticmethod
    def _mutate_content(data: bytes) -> bytes:
        """
        Мутация содержимого файла для изменения хэша.

        Для текстовых файлов: добавляем/меняем trailing whitespace.
        Для бинарных: меняем padding в конце.
        """
        try:
            text = data.decode("utf-8")
            # Текстовый файл: добавляем или меняем количество
            # пробелов/переносов в конце
            text = text.rstrip()
            # Добавляем случайное количество пробелов и newline
            padding = " " * random.randint(1, 8) + "\n"
            return (text + padding).encode("utf-8")
        except UnicodeDecodeError:
            # Бинарный файл: для zip-based форматов (docx, xlsx, pptx)
            # добавляем zip-комментарий, чтобы не сломать структуру.
            # Для остальных — меняем последние 4 байта.
            if data[:4] == b"PK\x03\x04":
                import struct as _struct
                comment = os.urandom(8)
                # Ищем End of Central Directory (PK\x05\x06)
                eocd_pos = data.rfind(b"PK\x05\x06")
                if eocd_pos >= 0 and eocd_pos + 22 <= len(data):
                    # Сохраняем структуру EOCD и хвост, заменяя комментарий.
                    old_len = _struct.unpack_from("<H", data, eocd_pos + 20)[0]
                    tail_offset = eocd_pos + 22 + old_len
                    if tail_offset <= len(data):
                        head = data[:eocd_pos + 20]
                        tail = data[tail_offset:]
                        return head + _struct.pack("<H", len(comment)) + comment + tail
            marker = os.urandom(4)
            if len(data) >= 4:
                return data[:-4] + marker
            return data + marker

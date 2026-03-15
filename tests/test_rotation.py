"""Тесты ротации ловушек."""

import asyncio
import os
import time
from unittest.mock import MagicMock


from phantom.factory.rotation import TrapRotator


class _FakeEntry:
    def __init__(self, path: str, trap_id: str = "TRAP-001"):
        self.output_path = path
        self.trap_id = trap_id


class _FakeRegistry:
    def __init__(self, entries):
        self._entries = entries

    def entries(self):
        return self._entries


def test_rotator_disabled():
    reg = _FakeRegistry([])
    rotator = TrapRotator(reg, lambda x: None, config={"enabled": False})
    rotator.start()
    assert rotator._running is False


def test_rotator_mutate_text():
    data = b"Hello World\n"
    result = TrapRotator._mutate_content(data)
    assert result != data
    assert b"Hello World" in result


def test_rotator_mutate_binary():
    data = bytes(range(256))
    result = TrapRotator._mutate_content(data)
    # Размер может измениться на 4 байта (padding)
    assert result != data


def test_rotator_mutate_empty_text():
    data = b""
    result = TrapRotator._mutate_content(data)
    assert len(result) > 0


def test_rotate_batch(tmp_path):
    # Создаём файлы-ловушки
    files = []
    for i in range(5):
        f = tmp_path / f"trap_{i}.txt"
        f.write_text(f"content {i}")
        # Ставим mtime в прошлое
        old_time = time.time() - 7200  # 2 часа назад
        os.utime(f, (old_time, old_time))
        files.append(f)

    entries = [_FakeEntry(str(f)) for f in files]
    reg = _FakeRegistry(entries)
    callback = MagicMock()
    rotator = TrapRotator(
        reg, callback,
        config={"enabled": True, "batch_size": 3, "min_age_seconds": 60},
    )

    async def _run():
        rotated = await rotator.rotate_batch()
        assert rotated == 3
        callback.assert_called_once()

    asyncio.run(_run())


def test_rotate_batch_skips_young_files(tmp_path):
    f = tmp_path / "new_trap.txt"
    f.write_text("fresh content")
    # Файл только что создан — не должен ротироваться

    entries = [_FakeEntry(str(f))]
    reg = _FakeRegistry(entries)
    rotator = TrapRotator(
        reg, lambda x: None,
        config={"enabled": True, "batch_size": 5, "min_age_seconds": 3600},
    )

    async def _run():
        rotated = await rotator.rotate_batch()
        assert rotated == 0

    asyncio.run(_run())


def test_rotate_batch_empty_registry():
    reg = _FakeRegistry([])
    rotator = TrapRotator(reg, lambda x: None, config={"enabled": True})

    async def _run():
        assert await rotator.rotate_batch() == 0

    asyncio.run(_run())


def test_rotate_batch_nonexistent_file():
    entries = [_FakeEntry("/nonexistent/path/trap.txt")]
    reg = _FakeRegistry(entries)
    rotator = TrapRotator(
        reg, lambda x: None,
        config={"enabled": True, "min_age_seconds": 0},
    )

    async def _run():
        assert await rotator.rotate_batch() == 0

    asyncio.run(_run())


def test_rotator_start_stop():
    reg = _FakeRegistry([])
    rotator = TrapRotator(
        reg, lambda x: None,
        config={"enabled": True, "interval_seconds": 60},
    )
    loop = asyncio.new_event_loop()
    rotator.start(loop)
    loop.run_until_complete(asyncio.sleep(0))
    assert rotator._running is True
    rotator.stop()
    loop.run_until_complete(asyncio.sleep(0))
    assert rotator._running is False
    loop.close()

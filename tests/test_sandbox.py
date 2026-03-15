"""Тесты Docker-песочницы."""

from phantom.response.sandbox import SandboxRunner, SandboxResult


def test_sandbox_result_to_dict():
    r = SandboxResult(
        container_id="abc123",
        container_name="phantom_sandbox_test",
        exit_code=0,
        logs="some output",
        artifacts=["/tmp/output.tar"],
        duration_seconds=5.2,
        timed_out=False,
    )
    d = r.to_dict()
    assert d["container_id"] == "abc123"
    assert d["exit_code"] == 0
    assert d["timed_out"] is False
    assert d["duration_seconds"] == 5.2
    assert len(d["artifacts"]) == 1


def test_sandbox_result_timed_out():
    r = SandboxResult(
        container_id="",
        container_name="test",
        exit_code=-1,
        logs="",
        timed_out=True,
    )
    assert r.timed_out is True


def test_sandbox_random_suffix():
    s1 = SandboxRunner._random_suffix()
    s2 = SandboxRunner._random_suffix()
    assert len(s1) == 8
    assert s1 != s2


def test_sandbox_available_false():
    """Без Docker клиент sandbox.available = False."""
    runner = SandboxRunner()
    assert runner.available is False


def test_sandbox_analyze_without_docker():
    """analyze() возвращает None без Docker."""
    import asyncio
    from phantom.core.state import Context, Event, EventType, Severity

    async def _run():
        runner = SandboxRunner()
        runner._initialized = True  # Пропускаем инициализацию
        event = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/test",
            source_sensor="fanotify",
            severity=Severity.HIGH,
        )
        ctx = Context(event=event, threat_score=1.0)
        result = await runner.analyze(ctx)
        assert result is None

    asyncio.run(_run())


def test_sandbox_analyze_missing_config():
    """analyze() возвращает None при отсутствии image/command."""
    import asyncio
    from phantom.core.state import Context, Event, EventType, Severity

    async def _run():
        runner = SandboxRunner()
        runner._initialized = True
        runner._docker = object()
        runner._config = {}
        event = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/test",
            source_sensor="fanotify",
            severity=Severity.HIGH,
        )
        ctx = Context(event=event, threat_score=1.0)
        result = await runner.analyze(ctx)
        assert result is None

    asyncio.run(_run())


def test_sandbox_safe_extract_tar(tmp_path):
    import io
    import tarfile

    runner = SandboxRunner()
    tar_path = tmp_path / "output.tar"
    with tarfile.open(tar_path, "w") as tf:
        data = b"ok"
        info = tarfile.TarInfo("good.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

        bad = tarfile.TarInfo("../evil.txt")
        bad.size = len(data)
        tf.addfile(bad, io.BytesIO(data))

    target = tmp_path / "out"
    with tarfile.open(tar_path, "r") as tf:
        runner._safe_extract_tar(tf, target)

    assert (target / "good.txt").read_text(encoding="utf-8") == "ok"
    assert not (tmp_path / "evil.txt").exists()


def test_sandbox_cleanup_old_containers():
    import asyncio
    from datetime import datetime, timedelta, timezone

    class _Container:
        def __init__(self, created):
            self.attrs = {"Created": created}
            self.removed = False

        def remove(self, force=True):  # noqa: ANN001
            self.removed = True

    class _Containers:
        def __init__(self, items):
            self._items = items

        def list(self, *args, **kwargs):  # noqa: ANN001
            return self._items

    class _Docker:
        def __init__(self, items):
            self.containers = _Containers(items)

    now = datetime.now(timezone.utc)
    old = _Container((now - timedelta(hours=5)).isoformat())
    fresh = _Container((now - timedelta(hours=0.5)).isoformat())

    runner = SandboxRunner()
    runner._initialized = True
    runner._docker = _Docker([old, fresh])

    removed = asyncio.run(runner.cleanup_old_containers(max_age_hours=1))
    assert removed == 1
    assert old.removed is True
    assert fresh.removed is False

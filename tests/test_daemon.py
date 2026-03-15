"""Тесты daemon wrapper."""

from phantom.daemon import DaemonService


def test_daemon_service_run_returns_code():
    async def _start():
        return 0

    svc = DaemonService(_start)
    assert svc.run() == 0

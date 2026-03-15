"""Тесты NetworkCollector."""

import socket
import sys
import types

import phantom.telemetry.network as net


def test_network_collector_fallback(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):  # noqa: ANN001
        if name == "psutil":
            raise ImportError("no psutil")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    collector = net.NetworkCollector()
    info = collector._collect_sync(123)
    assert info is not None
    assert info.local_addr == socket.gethostname()


def test_network_collector_with_psutil(monkeypatch):
    class _Conn:
        laddr = types.SimpleNamespace(ip="127.0.0.1", port=1234)
        raddr = types.SimpleNamespace(ip="1.1.1.1", port=80)
        type = socket.SOCK_STREAM
        status = "ESTABLISHED"
        fd = 7

    class _Proc:
        def __init__(self, pid):  # noqa: ANN001
            self.pid = pid

        def connections(self, kind="inet"):  # noqa: ANN001
            return [_Conn()]

    dummy = types.SimpleNamespace(Process=_Proc)
    monkeypatch.setitem(sys.modules, "psutil", dummy)

    collector = net.NetworkCollector()
    info = collector._collect_sync(123)
    assert info is not None
    assert info.local_addr == "127.0.0.1"
    assert len(info.connections) == 1

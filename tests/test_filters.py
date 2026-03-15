"""Тесты утилит фильтрации сенсоров."""

import types

import phantom.sensors.filters as filters


def test_debounce_filter_window(monkeypatch):
    times = iter([100.0, 100.5, 101.1])
    monkeypatch.setattr(filters.time, "time", lambda: next(times))
    df = filters.DebounceFilter(window_seconds=1.0)
    assert df.allow("k") is True
    assert df.allow("k") is False
    assert df.allow("k") is True


def test_path_match_patterns():
    assert filters.path_match("/tmp/test.txt", ["*.txt"]) is True
    assert filters.path_match("/tmp/test.log", ["*.txt"]) is False
    assert filters.path_match("/tmp/test.log", None) is False


def test_resolve_pid_for_path(monkeypatch):
    def _fake_run(*args, **kwargs):  # noqa: ANN001
        return types.SimpleNamespace(returncode=0, stdout="123\n", stderr="")

    monkeypatch.setattr(filters.subprocess, "run", _fake_run)
    monkeypatch.setattr(filters.Path, "read_text", lambda self, **kwargs: "cmd")  # noqa: ANN001
    pid, name = filters.resolve_pid_for_path("/tmp/file")
    assert pid == 123
    assert name == "cmd"


def test_resolve_pid_for_path_invalid(monkeypatch):
    def _fake_run(*args, **kwargs):  # noqa: ANN001
        return types.SimpleNamespace(returncode=0, stdout="not-a-pid\n", stderr="")

    monkeypatch.setattr(filters.subprocess, "run", _fake_run)
    pid, name = filters.resolve_pid_for_path("/tmp/file")
    assert pid is None
    assert name is None

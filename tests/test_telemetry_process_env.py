"""Тесты безопасного сбора env-переменных процесса."""

import phantom.telemetry.processes as processes


class _DummyProc:
    def __init__(self, data):
        self._data = data

    def environ(self):  # noqa: D401
        return self._data


def test_env_collection_disabled(monkeypatch):
    monkeypatch.setattr(processes, "get_config", lambda: {"telemetry": {"process": {"collect_env": False}}})
    collector = processes.ProcessCollector()
    proc = _DummyProc({"SAFE": "ok"})
    assert collector._safe_env(proc) == {}


def test_env_collection_allowlist_and_limits(monkeypatch):
    cfg = {
        "telemetry": {
            "process": {
                "collect_env": True,
                "env_allowlist": ["SAFE", "KEEP"],
                "env_denylist": ["KEEP"],
                "max_env_entries": 1,
                "max_env_value_len": 4,
            }
        }
    }
    monkeypatch.setattr(processes, "get_config", lambda: cfg)
    collector = processes.ProcessCollector()
    proc = _DummyProc({"SAFE": "123456789", "KEEP": "secret", "OTHER": "x"})
    env = collector._safe_env(proc)
    assert "SAFE" in env
    assert "KEEP" not in env
    assert len(env) == 1
    assert env["SAFE"].endswith("...")

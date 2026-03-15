"""Тесты runtime-защиты экспортёров."""

import socket

import phantom.response.exporters as exporters


def test_runtime_check_blocks_private(monkeypatch):
    def _fake_getaddrinfo(*args, **kwargs):  # noqa: ANN001
        return [
            (socket.AF_INET, None, None, None, ("10.0.0.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert exporters._is_safe_url_runtime("https://example.com/webhook") is False


def test_runtime_check_allows_public(monkeypatch):
    def _fake_getaddrinfo(*args, **kwargs):  # noqa: ANN001
        return [
            (socket.AF_INET, None, None, None, ("1.1.1.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    assert exporters._is_safe_url_runtime("https://example.com/webhook") is True


def test_sanitize_payload_strips_environ():
    payload = {
        "context": {
            "process": {
                "pid": 123,
                "environ": {"TOKEN": "secret"},
            }
        }
    }
    sanitized = exporters.AlertExporter._sanitize_payload(payload)
    assert "environ" not in sanitized["context"]["process"]


def test_retry_pending_includes_telegram(tmp_path, monkeypatch):
    def _fake_get_config():
        return {
            "integrations": {"telegram_enabled": True},
            "paths": {"logs_dir": str(tmp_path)},
        }

    monkeypatch.setattr(exporters, "get_config", _fake_get_config)
    exporter = exporters.AlertExporter()
    exporter._webhooks = []
    exporter._syslog_enabled = False
    exporter._pending_queue.clear()
    exporter._pending_queue.append({"decision": {"priority": "high"}, "context": {"event": {}}})

    calls = {"telegram": 0}

    def _emit(payload):  # noqa: ANN001
        calls["telegram"] += 1
        return True

    monkeypatch.setattr(exporter, "_emit_telegram", _emit)
    monkeypatch.setattr(exporter, "_save_pending_queue", lambda: None)

    exporter._retry_pending()
    assert calls["telegram"] == 1
    assert len(exporter._pending_queue) == 0

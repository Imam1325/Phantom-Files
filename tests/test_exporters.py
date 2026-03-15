"""Тесты экспортёров алертов (SSRF, retry, очередь)."""

from phantom.response.exporters import _is_safe_url


# ---------- SSRF-защита ----------

def test_safe_url_public():
    # Публичный URL — безопасен
    assert _is_safe_url("https://hooks.slack.com/services/abc") is True


def test_safe_url_rejects_localhost():
    assert _is_safe_url("http://localhost:8080/webhook") is False
    assert _is_safe_url("http://127.0.0.1/webhook") is False


def test_safe_url_rejects_private_10():
    assert _is_safe_url("http://10.0.0.1/webhook") is False


def test_safe_url_rejects_private_172():
    assert _is_safe_url("http://172.16.0.1/webhook") is False


def test_safe_url_rejects_private_192():
    assert _is_safe_url("http://192.168.1.1/webhook") is False


def test_safe_url_rejects_metadata():
    assert _is_safe_url("http://169.254.169.254/latest/meta-data/") is False


def test_safe_url_rejects_file_scheme():
    assert _is_safe_url("file:///etc/passwd") is False


def test_safe_url_rejects_empty():
    assert _is_safe_url("") is False


def test_safe_url_rejects_no_host():
    assert _is_safe_url("http:///path") is False


def test_safe_url_rejects_ipv6_loopback():
    assert _is_safe_url("http://[::1]/webhook") is False

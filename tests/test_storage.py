"""Тесты хранения улик (шифрование fail-closed)."""

import base64

import pytest

from phantom.response.storage import EvidenceStorage, _Base64Encoder


def _make_file(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _make_storage():
    storage = EvidenceStorage()
    storage._enabled = True
    storage._client = object()
    return storage


def test_encrypt_invalid_base64_fails_closed(tmp_path, monkeypatch):
    storage = _make_storage()
    monkeypatch.setenv(storage._encryption_key_env, "not-base64!!!")
    called = {"count": 0}

    def _upload(_path):
        called["count"] += 1
        return "s3://bucket/key"

    storage._upload_file = _upload
    bundle = _make_file(tmp_path, "bundle.tar.gz", b"data")
    manifest = _make_file(tmp_path, "manifest.json", b"{}")
    uploaded = storage.store(bundle, manifest)
    assert uploaded == []
    assert called["count"] == 0


def test_encrypt_wrong_length_fails_closed(tmp_path, monkeypatch):
    storage = _make_storage()
    bad_key = base64.b64encode(b"x" * 16).decode("ascii")
    monkeypatch.setenv(storage._encryption_key_env, bad_key)
    called = {"count": 0}

    def _upload(_path):
        called["count"] += 1
        return "s3://bucket/key"

    storage._upload_file = _upload
    bundle = _make_file(tmp_path, "bundle.tar.gz", b"data")
    manifest = _make_file(tmp_path, "manifest.json", b"{}")
    uploaded = storage.store(bundle, manifest)
    assert uploaded == []
    assert called["count"] == 0


def test_base64_encoder_chunks():
    enc = _Base64Encoder()
    out = enc.encode(b"ab") + enc.encode(b"c") + enc.finalize()
    assert out == base64.b64encode(b"abc")


def test_encrypt_no_key_returns_path(tmp_path, monkeypatch):
    storage = _make_storage()
    monkeypatch.delenv(storage._encryption_key_env, raising=False)
    src = _make_file(tmp_path, "bundle.tar.gz", b"data")
    out = storage._encrypt_if_configured(src)
    assert out == src


def test_encrypt_valid_key_creates_bundle(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    storage = _make_storage()
    key = base64.b64encode(b"\x01" * 32).decode("ascii")
    monkeypatch.setenv(storage._encryption_key_env, key)
    src = _make_file(tmp_path, "bundle.tar.gz", b"data")
    out = storage._encrypt_if_configured(src)
    assert out is not None
    assert out.exists()
    payload = out.read_text(encoding="utf-8")
    assert '"alg":"AES-256-GCM"' in payload

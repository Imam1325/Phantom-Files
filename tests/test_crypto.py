"""Тесты криптографических утилит (utils/crypto.py)."""

from pathlib import Path

import pytest

from phantom.utils.crypto import (
    hash_file,
    md5_file,
    sha1_file,
    sha256_file,
    random_token,
    uuid4_str,
    watermark_id,
    sign_ed25519,
)


# ---------- random_token ----------

def test_random_token_default_length():
    token = random_token()
    assert isinstance(token, str)
    assert len(token) == 32  # 32 // 2 = 16 bytes = 32 hex chars


def test_random_token_custom_length():
    token = random_token(64)
    assert len(token) == 64


def test_random_token_min_length():
    """length=0 → max(1, 0) = 1 byte = 2 hex chars."""
    token = random_token(0)
    assert len(token) == 2


def test_random_token_uniqueness():
    tokens = {random_token() for _ in range(100)}
    assert len(tokens) == 100


# ---------- uuid4_str ----------

def test_uuid4_str_format():
    uid = uuid4_str()
    assert isinstance(uid, str)
    assert len(uid) == 36
    parts = uid.split("-")
    assert len(parts) == 5


def test_uuid4_str_unique():
    uids = {uuid4_str() for _ in range(50)}
    assert len(uids) == 50


# ---------- hash_file ----------

def test_hash_file_sha256(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    result = hash_file(str(f), "sha256")
    assert result is not None
    assert len(result) == 64  # sha256 hex


def test_hash_file_md5(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    result = hash_file(str(f), "md5")
    assert result is not None
    assert len(result) == 32


def test_hash_file_nonexistent():
    assert hash_file("/nonexistent/path.txt", "sha256") is None


def test_hash_file_empty(tmp_path: Path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    result = hash_file(str(f), "sha256")
    assert result is not None
    # SHA256 of empty string
    assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_file_deterministic(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00\x01\x02\x03" * 1000)
    h1 = hash_file(str(f), "sha256")
    h2 = hash_file(str(f), "sha256")
    assert h1 == h2


# ---------- md5_file / sha1_file / sha256_file ----------

def test_md5_file(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("test")
    assert md5_file(str(f)) is not None
    assert len(md5_file(str(f))) == 32


def test_sha1_file(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("test")
    assert sha1_file(str(f)) is not None
    assert len(sha1_file(str(f))) == 40


def test_sha256_file(tmp_path: Path):
    f = tmp_path / "t.txt"
    f.write_text("test")
    assert sha256_file(str(f)) is not None
    assert len(sha256_file(str(f))) == 64


def test_md5_file_nonexistent():
    assert md5_file("/no/such/file") is None


def test_sha1_file_nonexistent():
    assert sha1_file("/no/such/file") is None


def test_sha256_file_nonexistent():
    assert sha256_file("/no/such/file") is None


# ---------- watermark_id ----------

def test_watermark_id_default_prefix():
    wid = watermark_id()
    assert wid.startswith("wt-")
    assert len(wid) == 3 + 12  # "wt-" + 12 hex


def test_watermark_id_custom_prefix():
    wid = watermark_id(prefix="ph")
    assert wid.startswith("ph-")


def test_watermark_id_unique():
    ids = {watermark_id() for _ in range(100)}
    assert len(ids) == 100


# ---------- sign_ed25519 ----------

def test_sign_ed25519_roundtrip():
    """Подпись Ed25519 верифицируется публичным ключом."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    data = b"test data to sign"
    sig = sign_ed25519(pem, data)
    assert isinstance(sig, bytes)
    assert len(sig) == 64  # Ed25519 подпись всегда 64 байта

    # Верификация
    public_key = private_key.public_key()
    public_key.verify(sig, data)  # Не бросает = верно


def test_sign_ed25519_with_passphrase():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret123"),
    )
    sig = sign_ed25519(pem, b"data", passphrase="secret123")
    assert len(sig) == 64


def test_sign_ed25519_wrong_key_type():
    """RSA-ключ вместо Ed25519 вызывает RuntimeError."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(RuntimeError, match="not Ed25519"):
        sign_ed25519(pem, b"data")


def test_sign_ed25519_invalid_pem():
    pytest.importorskip("cryptography")
    with pytest.raises(Exception):
        sign_ed25519(b"not a pem key", b"data")

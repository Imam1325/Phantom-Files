"""
Криптографические утилиты Phantom v1.0.0.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from pathlib import Path
from typing import Optional


def random_token(length: int = 32) -> str:
    try:
        length = int(length)
    except (TypeError, ValueError):
        length = 32
    if length <= 0:
        length = 2
    return secrets.token_hex((length + 1) // 2)[:length]


def uuid4_str() -> str:
    return str(uuid.uuid4())


def hash_file(path: str, algo: str) -> Optional[str]:
    file_path = Path(path)
    if not file_path.exists():
        return None
    hasher = hashlib.new(algo)
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def md5_file(path: str) -> Optional[str]:
    return hash_file(path, "md5")


def sha1_file(path: str) -> Optional[str]:
    return hash_file(path, "sha1")


def sha256_file(path: str) -> Optional[str]:
    return hash_file(path, "sha256")


def watermark_id(prefix: str = "wt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def sign_ed25519(private_key_pem: bytes, data: bytes, passphrase: Optional[str] = None) -> bytes:
    """
    Возвращает отделённую подпись Ed25519.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as exc:
        raise RuntimeError("cryptography package is required for Ed25519 signing") from exc

    key = serialization.load_pem_private_key(
        private_key_pem,
        password=passphrase.encode("utf-8") if passphrase else None,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Configured key is not Ed25519")
    return key.sign(data)

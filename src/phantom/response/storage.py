"""
Интеграция хранилища улик (S3/MinIO) с опциональным шифрованием AES-256-GCM.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from phantom.core.config import get_config

logger = logging.getLogger("phantom.storage")


class _Base64Encoder:
    """Потоковый base64-энкодер: корректно обрабатывает произвольные куски данных."""

    def __init__(self) -> None:
        self._buffer = b""

    def encode(self, data: bytes) -> bytes:
        if not data:
            return b""
        data = self._buffer + data
        rem = len(data) % 3
        if rem:
            self._buffer = data[-rem:]
            data = data[:-rem]
        else:
            self._buffer = b""
        return base64.b64encode(data) if data else b""

    def finalize(self) -> bytes:
        if not self._buffer:
            return b""
        out = base64.b64encode(self._buffer)
        self._buffer = b""
        return out


class EvidenceStorage:
    def __init__(self) -> None:
        cfg = get_config()
        forensics_cfg = cfg.get("forensics", {})
        self._s3_cfg = forensics_cfg.get("s3", {})
        self._enabled = bool(self._s3_cfg.get("enabled", False))
        self._client = None
        self._bucket = str(self._s3_cfg.get("bucket", "")).strip()
        self._prefix = str(self._s3_cfg.get("prefix", "evidence")).strip().strip("/")
        self._encryption_key_env = str(self._s3_cfg.get("encryption_key_env", "PHANTOM_EVIDENCE_KEY_B64"))
        self._object_lock_days = int(self._s3_cfg.get("object_lock_days", 90))
        self._upload_timeout = int(self._s3_cfg.get("upload_timeout_seconds", 30))

        if self._enabled:
            self._init_s3_client()

    def store(self, bundle_path: Path, manifest_path: Path) -> list[str]:
        if not self._enabled or self._client is None:
            return []
        encrypted_bundle = self._encrypt_if_configured(bundle_path)
        encrypted_manifest = self._encrypt_if_configured(manifest_path)
        if encrypted_bundle is None or encrypted_manifest is None:
            logger.error("Evidence encryption failed; upload aborted")
            return []

        uploaded: list[str] = []
        bundle_uri = self._upload_file(encrypted_bundle)
        if bundle_uri:
            uploaded.append(bundle_uri)
        manifest_uri = self._upload_file(encrypted_manifest)
        if manifest_uri:
            uploaded.append(manifest_uri)
        return uploaded

    def _init_s3_client(self) -> None:
        try:
            import boto3  # type: ignore
            from botocore.config import Config  # type: ignore
        except Exception as exc:
            logger.error("S3 storage requested but boto3 unavailable: %s", exc)
            self._enabled = False
            return

        access_key_env = str(self._s3_cfg.get("access_key_env", "PHANTOM_S3_ACCESS_KEY"))
        secret_key_env = str(self._s3_cfg.get("secret_key_env", "PHANTOM_S3_SECRET_KEY"))
        access_key = os.getenv(access_key_env, "").strip()
        secret_key = os.getenv(secret_key_env, "").strip()
        endpoint_url = str(self._s3_cfg.get("endpoint_url", "")).strip() or None
        region = str(self._s3_cfg.get("region", "us-east-1")).strip()
        verify_tls = bool(self._s3_cfg.get("verify_tls", True))

        if not self._bucket:
            logger.error("S3 storage enabled but bucket is empty")
            self._enabled = False
            return
        if not access_key or not secret_key:
            logger.error("S3 storage enabled but credentials are missing in environment")
            self._enabled = False
            return

        cfg = Config(connect_timeout=self._upload_timeout, read_timeout=self._upload_timeout, retries={"max_attempts": 3})
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            verify=verify_tls,
            config=cfg,
        )

    def _encrypt_if_configured(self, path: Path) -> Optional[Path]:
        key_raw = os.getenv(self._encryption_key_env, "").strip()
        if not key_raw:
            return path
        try:
            key = base64.b64decode(key_raw, validate=True)
            if len(key) != 32:
                logger.error("Invalid evidence encryption key length; expected 32 bytes after base64 decode")
                return None
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception as exc:
            logger.error("Evidence encryption setup failed: %s", exc)
            return None

        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encrypted_path = path.with_suffix(path.suffix + ".enc.json")
        encoder = _Base64Encoder()
        try:
            with path.open("rb") as src, encrypted_path.open("w", encoding="utf-8") as out:
                prefix = (
                    '{"alg":"AES-256-GCM","nonce_b64":'
                    + json.dumps(base64.b64encode(nonce).decode("ascii"))
                    + ',"source":'
                    + json.dumps(path.name)
                    + ',"ciphertext_b64":"'
                )
                out.write(prefix)
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    ct = encryptor.update(chunk)
                    if ct:
                        out.write(encoder.encode(ct).decode("ascii"))
                final_ct = encryptor.finalize()
                tail = final_ct + encryptor.tag
                if tail:
                    out.write(encoder.encode(tail).decode("ascii"))
                out.write(encoder.finalize().decode("ascii"))
                out.write('"}')
        except Exception as exc:
            logger.error("Evidence encryption failed: %s", exc)
            return None
        return encrypted_path

    def _upload_file(self, path: Path) -> Optional[str]:
        if self._client is None:
            return None
        now = datetime.now(timezone.utc)
        key = f"{self._prefix}/{now.strftime('%Y/%m/%d')}/{path.name}"
        extra_args: dict[str, object] = {}
        if self._object_lock_days > 0:
            retain_until = now + timedelta(days=self._object_lock_days)
            extra_args["ObjectLockMode"] = "COMPLIANCE"
            extra_args["ObjectLockRetainUntilDate"] = retain_until
        try:
            self._client.upload_file(
                Filename=str(path),
                Bucket=self._bucket,
                Key=key,
                ExtraArgs=extra_args or None,
            )
            return f"s3://{self._bucket}/{key}"
        except Exception as exc:
            logger.error("S3 upload failed file=%s error=%s", path, exc)
            return None

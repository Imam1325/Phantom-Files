"""
JWT-аутентификация (self-issued HMAC-SHA256).

Модуль реализует выпуск и валидацию JWT-токенов без внешнего IdP.
Ключ подписи берётся из переменной окружения PHANTOM_JWT_SECRET.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

import jwt  # PyJWT

logger = logging.getLogger("phantom.api.auth")

# Минимальная длина секрета (256 бит = 32 байта)
_MIN_SECRET_LENGTH = 32
# Время жизни access-токена (30 минут)
_ACCESS_TTL_SECONDS = 30 * 60
# Время жизни refresh-токена (7 дней)
_REFRESH_TTL_SECONDS = 7 * 24 * 3600
# Алгоритм подписи
_ALGORITHM = "HS256"
# Издатель токена
_ISSUER = "phantom-daemon"


@dataclass(frozen=True)
class TokenClaims:
    """Распарсенные данные из JWT-токена."""
    sub: str
    role: str
    token_type: str  # "access" | "refresh"
    exp: int
    iat: int
    jti: str


class JWTProvider:
    """
    Провайдер JWT-токенов с HMAC-SHA256.

    Безопасность:
    - Секрет >= 32 байт (256 бит)
    - Constant-time верификация подписи (PyJWT использует hmac.compare_digest)
    - jti для предотвращения replay-атак
    - Раздельные access/refresh токены
    """

    def __init__(
        self,
        secret: str | None = None,
        access_ttl: int = _ACCESS_TTL_SECONDS,
        refresh_ttl: int = _REFRESH_TTL_SECONDS,
    ) -> None:
        self._secret = secret or os.getenv("PHANTOM_JWT_SECRET", "").strip()
        if not self._secret:
            raise ValueError(
                "JWT secret не задан. Установите переменную окружения "
                "PHANTOM_JWT_SECRET (минимум 32 символа)"
            )
        if len(self._secret) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"JWT secret слишком короткий: {len(self._secret)} < {_MIN_SECRET_LENGTH} символов"
            )
        self._access_ttl = max(60, access_ttl)
        self._refresh_ttl = max(300, refresh_ttl)
        # Отозванные jti с временем отзыва (in-memory; при перезапуске сбрасывается)
        self._revoked_jti: dict[str, float] = {}
        self._max_revoked = 10000
        self._revoked_lock = threading.Lock()

    def issue_access_token(self, subject: str, role: str) -> str:
        """Выпуск access-токена."""
        return self._issue(subject, role, "access", self._access_ttl)

    def issue_refresh_token(self, subject: str, role: str) -> str:
        """Выпуск refresh-токена."""
        return self._issue(subject, role, "refresh", self._refresh_ttl)

    def issue_token_pair(self, subject: str, role: str) -> dict[str, str]:
        """Выпуск пары access + refresh токенов."""
        return {
            "access_token": self.issue_access_token(subject, role),
            "refresh_token": self.issue_refresh_token(subject, role),
            "token_type": "Bearer",
            "expires_in": self._access_ttl,
        }

    def validate(self, token: str) -> Optional[TokenClaims]:
        """
        Валидация и декодирование JWT-токена.

        Возвращает None при невалидном/просроченном/отозванном токене.
        """
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[_ALGORITHM],
                issuer=_ISSUER,
                options={
                    "require": ["sub", "role", "exp", "iat", "jti", "token_type"],
                    "verify_exp": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError:
            logger.debug("JWT expired")
            return None
        except jwt.InvalidTokenError as exc:
            logger.debug("JWT invalid: %s", exc)
            return None

        jti = str(payload.get("jti", ""))
        with self._revoked_lock:
            if jti in self._revoked_jti:
                logger.warning("JWT revoked jti=%s", jti)
                return None
            # Периодическая очистка протухших JTI
            if len(self._revoked_jti) > self._max_revoked:
                self._cleanup_revoked_locked()

        return TokenClaims(
            sub=str(payload["sub"]),
            role=str(payload["role"]).strip().lower() or "viewer",
            token_type=str(payload["token_type"]),
            exp=int(payload["exp"]),
            iat=int(payload["iat"]),
            jti=jti,
        )

    def refresh(self, refresh_token: str) -> Optional[dict[str, str]]:
        """
        Обновление токенов по refresh-токену.

        Старый refresh-токен отзывается после успешного обновления.
        """
        claims = self.validate(refresh_token)
        if claims is None:
            return None
        if claims.token_type != "refresh":
            logger.warning("Refresh attempt with non-refresh token")
            return None
        # Отзываем использованный refresh-токен (rotation)
        with self._revoked_lock:
            self._revoked_jti[claims.jti] = time.time()
        return self.issue_token_pair(claims.sub, claims.role)

    def revoke(self, jti: str) -> None:
        """Отзыв токена по jti."""
        with self._revoked_lock:
            self._revoked_jti[jti] = time.time()

    def _cleanup_revoked_locked(self) -> None:
        """Очистка протухших JTI (старше максимального TTL)."""
        max_ttl = max(self._access_ttl, self._refresh_ttl)
        cutoff = time.time() - max_ttl * 2
        expired = [jti for jti, ts in self._revoked_jti.items() if ts < cutoff]
        for jti in expired:
            del self._revoked_jti[jti]

    def _issue(self, subject: str, role: str, token_type: str, ttl: int) -> str:
        now = int(time.time())
        jti = hashlib.sha256(
            f"{subject}:{role}:{token_type}:{now}:{os.urandom(16).hex()}".encode()
        ).hexdigest()[:24]
        payload: dict[str, Any] = {
            "sub": subject,
            "role": role,
            "token_type": token_type,
            "iss": _ISSUER,
            "iat": now,
            "exp": now + ttl,
            "jti": jti,
        }
        return jwt.encode(payload, self._secret, algorithm=_ALGORITHM)


def get_jwt_provider(
    secret: str | None = None,
    access_ttl: int | None = None,
    refresh_ttl: int | None = None,
) -> Optional[JWTProvider]:
    """
    Фабрика JWTProvider. Возвращает None если секрет не задан.
    """
    secret = secret or os.getenv("PHANTOM_JWT_SECRET", "").strip()
    if not secret or len(secret) < _MIN_SECRET_LENGTH:
        return None
    kwargs: dict[str, Any] = {"secret": secret}
    if access_ttl is not None:
        kwargs["access_ttl"] = access_ttl
    if refresh_ttl is not None:
        kwargs["refresh_ttl"] = refresh_ttl
    try:
        return JWTProvider(**kwargs)
    except ValueError as exc:
        logger.error("JWT provider init failed: %s", exc)
        return None

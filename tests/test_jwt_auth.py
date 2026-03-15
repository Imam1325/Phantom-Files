"""Тесты JWT-аутентификации."""

import time

import pytest

from phantom.api.auth import JWTProvider, get_jwt_provider


SECRET = "a" * 64  # 64 символа — достаточно для HMAC-SHA256


def _provider(**kwargs) -> JWTProvider:
    return JWTProvider(secret=SECRET, **kwargs)


# ---------- Инициализация ----------

def test_provider_rejects_short_secret():
    with pytest.raises(ValueError, match="слишком короткий"):
        JWTProvider(secret="short")


def test_provider_rejects_empty_secret():
    with pytest.raises(ValueError, match="не задан"):
        JWTProvider(secret="")


def test_provider_accepts_valid_secret():
    p = _provider()
    assert p is not None


# ---------- Выпуск токенов ----------

def test_issue_access_token():
    p = _provider()
    token = p.issue_access_token("user1", "admin")
    assert isinstance(token, str)
    assert len(token) > 10


def test_issue_refresh_token():
    p = _provider()
    token = p.issue_refresh_token("user1", "viewer")
    assert isinstance(token, str)


def test_issue_token_pair():
    p = _provider()
    pair = p.issue_token_pair("user1", "editor")
    assert "access_token" in pair
    assert "refresh_token" in pair
    assert pair["token_type"] == "Bearer"
    assert pair["expires_in"] > 0


# ---------- Валидация ----------

def test_validate_access_token():
    p = _provider()
    token = p.issue_access_token("user1", "admin")
    claims = p.validate(token)
    assert claims is not None
    assert claims.sub == "user1"
    assert claims.role == "admin"
    assert claims.token_type == "access"


def test_validate_refresh_token():
    p = _provider()
    token = p.issue_refresh_token("user1", "viewer")
    claims = p.validate(token)
    assert claims is not None
    assert claims.token_type == "refresh"
    assert claims.role == "viewer"


def test_validate_expired_token():
    p = _provider(access_ttl=60)
    # Выпускаем токен и подделываем его exp
    import jwt as pyjwt
    payload = {
        "sub": "user1", "role": "admin", "token_type": "access",
        "iss": "phantom-daemon", "iat": int(time.time()) - 200,
        "exp": int(time.time()) - 100, "jti": "test123",
    }
    expired = pyjwt.encode(payload, SECRET, algorithm="HS256")
    assert p.validate(expired) is None


def test_validate_wrong_secret():
    p1 = _provider()
    p2 = JWTProvider(secret="b" * 64)
    token = p1.issue_access_token("user1", "admin")
    assert p2.validate(token) is None


def test_validate_garbage():
    p = _provider()
    assert p.validate("not.a.jwt") is None
    assert p.validate("") is None


def test_validate_wrong_issuer():
    import jwt as pyjwt
    p = _provider()
    payload = {
        "sub": "user1", "role": "admin", "token_type": "access",
        "iss": "wrong-issuer", "iat": int(time.time()),
        "exp": int(time.time()) + 3600, "jti": "test123",
    }
    token = pyjwt.encode(payload, SECRET, algorithm="HS256")
    assert p.validate(token) is None


# ---------- Refresh ----------

def test_refresh_token_rotation():
    p = _provider()
    pair = p.issue_token_pair("user1", "admin")
    new_pair = p.refresh(pair["refresh_token"])
    assert new_pair is not None
    assert "access_token" in new_pair
    # Старый refresh отозван
    assert p.refresh(pair["refresh_token"]) is None


def test_refresh_with_access_token_fails():
    p = _provider()
    access = p.issue_access_token("user1", "admin")
    assert p.refresh(access) is None


# ---------- Отзыв ----------

def test_revoke_token():
    p = _provider()
    token = p.issue_access_token("user1", "admin")
    claims = p.validate(token)
    assert claims is not None
    p.revoke(claims.jti)
    assert p.validate(token) is None


# ---------- Фабрика ----------

def test_get_jwt_provider_returns_none_for_short_secret():
    assert get_jwt_provider(secret="short") is None


def test_get_jwt_provider_returns_provider():
    p = get_jwt_provider(secret=SECRET)
    assert p is not None


def test_role_normalization():
    p = _provider()
    token = p.issue_access_token("user1", "  ADMIN  ")
    claims = p.validate(token)
    assert claims.role == "admin"

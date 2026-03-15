"""
ASGI-приложение на Starlette с JWT/API-key аутентификацией,
rate-limiting, Prometheus /metrics и /health.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from collections import defaultdict
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False

from phantom.api.auth import JWTProvider

logger = logging.getLogger("phantom.api.asgi")

# Лимит тела запроса (1 МБ)
MAX_BODY_SIZE = 1 * 1024 * 1024


class _BodyTooLarge(Exception):
    pass


# ---------- Prometheus метрики ----------
if _PROM_AVAILABLE:
    REQUEST_COUNT = Counter(
        "phantom_http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
    )
    REQUEST_LATENCY = Histogram(
        "phantom_http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "path"],
    )
    EVENTS_TOTAL = Gauge(
        "phantom_events_total",
        "Total processed events",
    )
    SENSOR_DEGRADED = Gauge(
        "phantom_sensor_degraded",
        "Sensor degraded flag (1 = degraded)",
    )


# ---------- Rate-limiter (token bucket per IP) ----------
class _TokenBucket:
    """Токен-бакет для одного IP-адреса."""

    __slots__ = ("tokens", "last_refill", "capacity", "rate")

    def __init__(self, capacity: float, rate: float) -> None:
        self.capacity = capacity
        self.rate = rate
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware для ограничения запросов по IP (token bucket).

    Пропускает /health и /metrics без лимитирования.
    """

    def __init__(self, app: Any, rate_per_minute: int = 60) -> None:
        super().__init__(app)
        rate_val = int(rate_per_minute)
        self._disabled = rate_val <= 0
        self._capacity = float(max(rate_val, 0))
        self._rate = rate_val / 60.0 if rate_val > 0 else 0.0
        self._buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(self._capacity, self._rate)
        )
        self._cleanup_counter = 0

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        path = request.url.path
        # Не лимитируем health/metrics
        if path in {"/health", "/api/v1/health", "/metrics"}:
            return await call_next(request)
        if self._disabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        bucket = self._buckets[client_ip]
        if not bucket.consume():
            retry_after = int(60 / self._rate) if self._rate > 0 else 60
            return JSONResponse(
                {"error": "rate_limit_exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        # Периодическая очистка старых бакетов (каждые 1000 запросов)
        self._cleanup_counter += 1
        if self._cleanup_counter >= 1000:
            self._cleanup_counter = 0
            self._cleanup_stale_buckets()

        return await call_next(request)

    def _cleanup_stale_buckets(self) -> None:
        """Удаляем бакеты, неактивные более 10 минут."""
        cutoff = time.monotonic() - 600
        stale = [ip for ip, b in self._buckets.items() if b.last_refill < cutoff]
        for ip in stale:
            del self._buckets[ip]


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware для ограничения размера тела запроса."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except (TypeError, ValueError):
                return JSONResponse(
                    {"error": "invalid_content_length"},
                    status_code=400,
                )
            if length < 0:
                return JSONResponse(
                    {"error": "invalid_content_length"},
                    status_code=400,
                )
            if length > MAX_BODY_SIZE:
                return JSONResponse(
                    {"error": "body_too_large"},
                    status_code=413,
                )
        return await call_next(request)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware для сбора Prometheus-метрик по HTTP-запросам."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if not _PROM_AVAILABLE:
            return await call_next(request)
        method = request.method
        path = self._normalize_path(request.url.path)
        start = time.monotonic()
        response = await call_next(request)
        elapsed = time.monotonic() - start
        REQUEST_COUNT.labels(method=method, path=path, status=response.status_code).inc()
        REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)
        return response

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Нормализация пути к шаблону маршрута для предотвращения cardinality explosion."""
        import re
        path = re.sub(r"/incidents/[^/]+", "/incidents/{id}", path)
        path = re.sub(r"/templates/[^/]+", "/templates/{name}", path)
        path = re.sub(r"/blocks/[^/]+", "/blocks/{id}", path)
        return path


# ---------- ASGI Application ----------

def create_asgi_app(
    *,
    health_provider: Callable[[], dict],
    control: Any = None,
    security_mode: str = "api_key",
    api_key: str | None = None,
    api_keys: dict[str, str] | None = None,
    jwt_provider: JWTProvider | None = None,
    rate_limit_per_minute: int = 60,
) -> Starlette:
    """
    Фабрика ASGI-приложения Phantom.

    Параметры:
    - health_provider: функция, возвращающая dict со статусом здоровья
    - control: экземпляр ControlPlane
    - security_mode: "api_key" | "jwt" | "both" | "mtls"
    - api_key: основной API-ключ (одиночный режим)
    - api_keys: словарь {token: role} для multi-key auth
    - jwt_provider: провайдер JWT-токенов
    - rate_limit_per_minute: лимит запросов в минуту на IP
    """
    _api_key = api_key
    _api_keys = dict(api_keys or {})
    _jwt = jwt_provider
    _security_mode = security_mode
    _health = health_provider
    _control = control

    # ---------- Вспомогательные функции ----------

    def _resolve_role(request: Request) -> str | None:
        """Определение роли из JWT или API-ключа."""
        mode = _security_mode
        if mode not in {"api_key", "jwt", "both", "mtls"}:
            mode = "api_key"

        if mode == "mtls":
            if _mtls_verified(request):
                return "admin"
            return None
        if mode == "both" and _mtls_verified(request):
            return "admin"

        # JWT проверка
        if mode in {"jwt", "both"}:
            role = _resolve_jwt(request)
            if role is not None:
                return role
            if mode == "jwt":
                return None

        # API-key проверка
        return _resolve_api_key(request)

    def _resolve_jwt(request: Request) -> str | None:
        if _jwt is None:
            return None
        auth = request.headers.get("authorization", "").strip()
        if not auth.startswith("Bearer "):
            return None
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            return None
        claims = _jwt.validate(token)
        if claims is None:
            return None
        if claims.token_type != "access":
            return None
        return claims.role

    def _resolve_api_key(request: Request) -> str | None:
        auth = request.headers.get("authorization", "").strip()
        if not _api_key and not _api_keys:
            return None
        if not auth.startswith("Bearer "):
            return None
        token = auth.removeprefix("Bearer ").strip()
        if not token:
            return None
        # Constant-time сравнение всех ключей
        matched_role: str | None = None
        for stored_token, role in _api_keys.items():
            if hmac.compare_digest(token.encode(), stored_token.encode()):
                matched_role = role
        if matched_role is not None:
            return str(matched_role).strip().lower() or "viewer"
        if _api_key and hmac.compare_digest(token.encode(), _api_key.encode()):
            return "admin"
        return None

    def _mtls_verified(request: Request) -> bool:
        """Проверка mTLS — заголовок принимается только от loopback (reverse proxy)."""
        client_ip = request.client.host if request.client else ""
        if client_ip not in {"127.0.0.1", "::1", "localhost"}:
            logger.warning(
                "mTLS header from non-loopback source %s — ignoring",
                client_ip,
            )
            return False
        value = request.headers.get("x-client-cert-verified", "").strip().lower()
        return value in {"1", "true", "yes", "success", "verified"}

    def _require_auth(request: Request, required_roles: set[str] | None = None) -> tuple[str | None, Response | None]:
        """Проверка авторизации. Возвращает (role, error_response)."""
        role = _resolve_role(request)
        if role is None:
            return None, JSONResponse({"error": "unauthorized"}, status_code=401)
        if required_roles and role not in required_roles:
            return role, JSONResponse({"error": "forbidden"}, status_code=403)
        return role, None

    async def _read_json(request: Request) -> tuple[dict | None, str | None]:
        """Чтение и парсинг JSON-тела запроса."""
        try:
            body = await _read_body_limited(request)
            if not body:
                return {}, None
            return json.loads(body.decode("utf-8")), None
        except _BodyTooLarge:
            return None, "body_too_large"
        except Exception:
            return None, "invalid_json"

    async def _read_body_limited(request: Request) -> bytes:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except (TypeError, ValueError):
                raise _BodyTooLarge()
            if length < 0 or length > MAX_BODY_SIZE:
                raise _BodyTooLarge()
            return await request.body()
        # Если Content-Length отсутствует (chunked), ограничиваем поток вручную.
        data = bytearray()
        async for chunk in request.stream():
            if chunk:
                data.extend(chunk)
                if len(data) > MAX_BODY_SIZE:
                    raise _BodyTooLarge()
        return bytes(data)

    # ---------- Обработчики маршрутов ----------

    async def health(request: Request) -> JSONResponse:
        data = _health()
        if _PROM_AVAILABLE:
            SENSOR_DEGRADED.set(1 if data.get("sensor_degraded") else 0)
            stats = data.get("orchestrator", {})
            EVENTS_TOTAL.set(stats.get("events_processed", 0))
        return JSONResponse(data)

    async def metrics(request: Request) -> Response:
        if not _PROM_AVAILABLE:
            return PlainTextResponse("prometheus_client not installed", status_code=501)
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    async def auth_token(request: Request) -> JSONResponse:
        """Эндпоинт выпуска JWT-токенов (POST /api/v1/auth/token)."""
        if _jwt is None:
            return JSONResponse({"error": "jwt_not_configured"}, status_code=501)
        payload, err = await _read_json(request)
        if err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        # Аутентификация через API-ключ для получения JWT
        role = _resolve_api_key(request)
        if role is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        subject = str(payload.get("subject", role)).strip() or role
        pair = _jwt.issue_token_pair(subject, role)
        return JSONResponse(pair)

    async def auth_refresh(request: Request) -> JSONResponse:
        """Эндпоинт обновления JWT-токенов (POST /api/v1/auth/refresh)."""
        if _jwt is None:
            return JSONResponse({"error": "jwt_not_configured"}, status_code=501)
        payload, err = await _read_json(request)
        if err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        refresh_token = str(payload.get("refresh_token", "")).strip()
        if not refresh_token:
            return JSONResponse({"error": "refresh_token_required"}, status_code=400)
        result = _jwt.refresh(refresh_token)
        if result is None:
            return JSONResponse({"error": "invalid_refresh_token"}, status_code=401)
        return JSONResponse(result)

    async def get_incidents(request: Request) -> JSONResponse:
        role, err = _require_auth(request)
        if err:
            return err
        if _control is not None:
            return JSONResponse(_control.list_incidents())
        return JSONResponse([])

    async def get_incident(request: Request) -> JSONResponse:
        role, err = _require_auth(request)
        if err:
            return err
        incident_id = request.path_params.get("incident_id", "").strip()
        if not incident_id:
            return JSONResponse({"error": "incident_id_required"}, status_code=400)
        if _control is not None:
            item = _control.get_incident(incident_id)
            if item is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            return JSONResponse(item)
        return JSONResponse({"error": "not_found"}, status_code=404)

    async def get_blocks(request: Request) -> JSONResponse:
        role, err = _require_auth(request)
        if err:
            return err
        if _control is not None:
            return JSONResponse(_control.list_blocks())
        return JSONResponse([])

    async def post_blocks(request: Request) -> JSONResponse:
        role, err = _require_auth(request, {"admin"})
        if err:
            return err
        payload, parse_err = await _read_json(request)
        if parse_err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if parse_err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if _control is not None:
            try:
                result = _control.create_block(payload, role=role)
                return JSONResponse(result, status_code=201)
            except PermissionError as exc:
                return JSONResponse({"error": "forbidden", "detail": str(exc)}, status_code=403)
            except Exception as exc:
                return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=400)
        return JSONResponse({"error": "not_available"}, status_code=503)

    async def get_templates(request: Request) -> JSONResponse:
        role, err = _require_auth(request)
        if err:
            return err
        if _control is not None:
            return JSONResponse(_control.list_templates())
        return JSONResponse([])

    async def post_templates(request: Request) -> JSONResponse:
        role, err = _require_auth(request, {"admin", "editor"})
        if err:
            return err
        payload, parse_err = await _read_json(request)
        if parse_err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if parse_err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if _control is not None:
            try:
                result = _control.mutate_templates(payload, role=role)
                return JSONResponse(result, status_code=201)
            except PermissionError as exc:
                return JSONResponse({"error": "forbidden", "detail": str(exc)}, status_code=403)
            except Exception as exc:
                return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=400)
        return JSONResponse({"error": "not_available"}, status_code=503)

    async def get_policies(request: Request) -> JSONResponse:
        role, err = _require_auth(request)
        if err:
            return err
        if _control is not None:
            return JSONResponse(_control.get_policies())
        return JSONResponse({})

    async def post_policies(request: Request) -> JSONResponse:
        role, err = _require_auth(request, {"admin"})
        if err:
            return err
        payload, parse_err = await _read_json(request)
        if parse_err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if parse_err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        # Запрет изменения mode через API
        if isinstance(payload, dict) and "mode" in payload:
            return JSONResponse(
                {"error": "mode_change_forbidden",
                 "detail": "Mode change is only allowed via CLI with root privileges"},
                status_code=403,
            )
        if _control is not None:
            try:
                result = _control.update_policies(payload, role=role, replace=False)
                return JSONResponse(result)
            except PermissionError as exc:
                return JSONResponse({"error": "forbidden", "detail": str(exc)}, status_code=403)
            except Exception as exc:
                return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=400)
        return JSONResponse({"error": "not_available"}, status_code=503)

    async def put_policies(request: Request) -> JSONResponse:
        role, err = _require_auth(request, {"admin"})
        if err:
            return err
        payload, parse_err = await _read_json(request)
        if parse_err == "body_too_large":
            return JSONResponse({"error": "body_too_large"}, status_code=413)
        if parse_err is not None:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "object_expected"}, status_code=400)
        if "mode" in payload:
            return JSONResponse(
                {"error": "mode_change_forbidden",
                 "detail": "Mode change is only allowed via CLI with root privileges"},
                status_code=403,
            )
        if _control is not None:
            try:
                result = _control.update_policies(payload, role=role, replace=True)
                return JSONResponse(result)
            except PermissionError as exc:
                return JSONResponse({"error": "forbidden", "detail": str(exc)}, status_code=403)
            except Exception as exc:
                return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=400)
        return JSONResponse({"error": "not_available"}, status_code=503)

    # ---------- Маршруты ----------
    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/api/v1/health", health, methods=["GET"]),
        Route("/metrics", metrics, methods=["GET"]),
        Route("/api/v1/auth/token", auth_token, methods=["POST"]),
        Route("/api/v1/auth/refresh", auth_refresh, methods=["POST"]),
        Route("/api/v1/incidents", get_incidents, methods=["GET"]),
        Route("/api/v1/incidents/{incident_id:str}", get_incident, methods=["GET"]),
        Route("/api/v1/blocks", get_blocks, methods=["GET"]),
        Route("/api/v1/blocks", post_blocks, methods=["POST"]),
        Route("/api/v1/templates", get_templates, methods=["GET"]),
        Route("/api/v1/templates", post_templates, methods=["POST"]),
        Route("/api/v1/policies", get_policies, methods=["GET"]),
        Route("/api/v1/policies", post_policies, methods=["POST"]),
        Route("/api/v1/policies", put_policies, methods=["PUT"]),
    ]

    middleware = [
        Middleware(RequestSizeLimitMiddleware),
        Middleware(RateLimitMiddleware, rate_per_minute=rate_limit_per_minute),
    ]
    if _PROM_AVAILABLE:
        middleware.append(Middleware(MetricsMiddleware))

    app = Starlette(routes=routes, middleware=middleware)
    return app

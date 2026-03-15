"""
Экспортёры алертов: webhook, syslog, telegram.

Безопасность:
- SSRF-защита: проверка URL на внутренние адреса
- Retry с экспоненциальной задержкой
- Очередь алертов с файловым бэкапом (JSONL)
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import os
import re
import socket
import time
from collections import deque
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from phantom.core.config import get_config
from phantom.core.state import Decision

logger = logging.getLogger("phantom.exporters")

# Максимум повторов при ошибке
_MAX_RETRIES = 3
# Базовая задержка между повторами (секунды)
_RETRY_BASE_DELAY = 1.0
# Максимальный размер in-memory очереди
_MAX_QUEUE_SIZE = 500
# Таймаут HTTP-запроса
_HTTP_TIMEOUT = 10


def _is_safe_url(url: str) -> bool:
    """
    Проверка URL на SSRF: запрет обращений к внутренним адресам.

    Блокирует:
    - localhost, 127.0.0.0/8, ::1
    - Приватные сети: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Link-local: 169.254.0.0/16, fe80::/10
    - Metadata сервисы облаков: 169.254.169.254
    """
    try:
        parsed = parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Запрет file:// и других опасных схем
        if parsed.scheme not in {"http", "https"}:
            return False
        lowered = hostname.strip().lower()
        if lowered in {"localhost", "localhost.localdomain"}:
            return False
        if lowered.endswith(".local"):
            return False
        # Если hostname — IP literal, проверяем сразу.
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            return True
        if not ip.is_global:
            return False
        if str(ip) == "169.254.169.254":
            return False
        return True
    except Exception:
        return False


def _is_safe_url_runtime(url: str) -> bool:
    """
    Runtime-проверка URL с DNS-резолвингом для защиты от DNS rebinding.
    """
    if not _is_safe_url(url):
        return False
    parsed = parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    # IP literal уже проверен в _is_safe_url
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for _family, _, _, _, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            return False
        if str(ip) == "169.254.169.254":
            return False
    return True


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise error.HTTPError(req.full_url, code, "Redirect blocked", headers, fp)


def _mask_url(url: str) -> str:
    """Маскирует токены в URL (например, /bot<token>/ -> /bot****/)."""
    return re.sub(r"/bot[^/]+/", "/bot****/", url)


def _retry_request(req: request.Request, max_retries: int = _MAX_RETRIES) -> bool:
    """
    Выполнение HTTP-запроса с экспоненциальной задержкой.

    Возвращает True при успехе (status < 300).
    """
    opener = request.build_opener(_NoRedirect())
    safe_url = _mask_url(req.full_url)
    for attempt in range(max_retries + 1):
        try:
            with opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
                if resp.status < 300:
                    return True
                logger.warning(
                    "HTTP %s (attempt %d/%d) url=%s",
                    resp.status, attempt + 1, max_retries + 1, safe_url,
                )
        except error.URLError as exc:
            logger.warning(
                "HTTP error (attempt %d/%d) url=%s: %s",
                attempt + 1, max_retries + 1, safe_url, exc,
            )
        if attempt < max_retries:
            delay = _RETRY_BASE_DELAY * (2 ** attempt)
            time.sleep(delay)
    return False


class AlertExporter:
    """Экспортёр алертов с поддержкой retry и очереди."""

    def __init__(self) -> None:
        cfg = get_config()
        integrations = cfg.get("integrations", {})
        raw_urls = integrations.get("webhook_urls", [])
        # Фильтрация URL: только безопасные
        self._webhooks: list[str] = []
        for url in raw_urls:
            url = str(url).strip()
            if not url:
                continue
            if _is_safe_url(url):
                self._webhooks.append(url)
            else:
                logger.error("Webhook URL blocked (SSRF): %s", url)

        self._telegram_enabled = bool(integrations.get("telegram_enabled", False))
        self._telegram_token_env = str(integrations.get("telegram_bot_token_env", "PHANTOM_TELEGRAM_BOT_TOKEN"))
        self._telegram_chat_id_env = str(integrations.get("telegram_chat_id_env", "PHANTOM_TELEGRAM_CHAT_ID"))

        self._syslog_enabled = bool(integrations.get("syslog_enabled", False))
        self._syslog_address = integrations.get("syslog_address", "/dev/log")
        self._syslog_facility = SysLogHandler.LOG_LOCAL0

        self._syslog_logger = logging.getLogger("phantom.exporters.syslog")
        self._syslog_logger.setLevel(logging.INFO)
        self._syslog_logger.propagate = False
        self._syslog_logger.handlers.clear()
        if self._syslog_enabled:
            handler = self._build_syslog_handler(self._syslog_address)
            if handler is not None:
                self._syslog_logger.addHandler(handler)

        # Файловая очередь для неотправленных алертов
        paths = cfg.get("paths", {})
        logs_dir = str(paths.get("logs_dir", "/var/log/phantom"))
        self._queue_path = Path(logs_dir) / "alert_queue.jsonl"
        self._pending_queue: deque[dict[str, Any]] = deque(maxlen=_MAX_QUEUE_SIZE)
        self._load_pending_queue()

    async def export_alert(self, decision: Decision) -> None:
        payload = {
            "decision": decision.to_dict(),
            "context": decision.context.to_dict(),
        }
        payload = self._sanitize_payload(payload)
        await asyncio.to_thread(self._export_sync, payload)

    def _export_sync(self, payload: dict[str, Any]) -> None:
        success = True
        if self._webhooks:
            for url in self._webhooks:
                if not self._emit_webhook(url, payload):
                    success = False
        if self._syslog_enabled:
            self._emit_syslog(payload)
        if self._telegram_enabled:
            if not self._emit_telegram(payload):
                success = False
        if not success:
            self._enqueue_failed(payload)
        # Попытка отправить ранее неотправленные алерты
        self._retry_pending()

    def _emit_webhook(self, url: str, payload: dict[str, Any]) -> bool:
        if not _is_safe_url_runtime(url):
            logger.error("Webhook URL blocked (SSRF): %s", url)
            return False
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = request.Request(url=url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        return _retry_request(req)

    def _emit_syslog(self, payload: dict[str, Any]) -> None:
        try:
            self._syslog_logger.info(json.dumps(payload, ensure_ascii=False))
        except Exception as exc:
            logger.error("Syslog export failed: %s", exc)

    def _emit_telegram(self, payload: dict[str, Any]) -> bool:
        token = os.getenv(self._telegram_token_env, "").strip()
        chat_id = os.getenv(self._telegram_chat_id_env, "").strip()
        if not token or not chat_id:
            return True  # Не настроен — не считаем ошибкой
        decision = payload.get("decision", {})
        context = payload.get("context", {})
        event = context.get("event", {})
        message = (
            "Phantom Alert\n"
            f"incident={context.get('incident_id')}\n"
            f"priority={decision.get('priority')}\n"
            f"event={event.get('event_type')}\n"
            f"path={event.get('target_path')}\n"
            f"pid={event.get('process_pid')}\n"
            f"sensor={event.get('source_sensor')}"
        )
        body = parse.urlencode({"chat_id": chat_id, "text": message[:3900]}).encode("utf-8")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        req = request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return _retry_request(req)

    def _enqueue_failed(self, payload: dict[str, Any]) -> None:
        """Сохранение неотправленного алерта в очередь."""
        self._pending_queue.append(payload)
        self._save_pending_queue()

    def _retry_pending(self) -> None:
        """Повторная отправка алертов из очереди (до 5 за раз)."""
        retried = 0
        while self._pending_queue and retried < 5:
            item = self._sanitize_payload(self._pending_queue[0])
            # Сохраняем отредактированную версию в очереди
            self._pending_queue[0] = item
            ok = True
            for url in self._webhooks:
                if not self._emit_webhook(url, item):
                    ok = False
                    break
            if self._syslog_enabled:
                self._emit_syslog(item)
            if self._telegram_enabled:
                if not self._emit_telegram(item):
                    ok = False
            if not ok:
                break  # Сервер недоступен, прекращаем
            self._pending_queue.popleft()
            retried += 1
        if retried > 0:
            self._save_pending_queue()

    def _load_pending_queue(self) -> None:
        """Загрузка неотправленных алертов из файла."""
        if not self._queue_path.exists():
            return
        try:
            lines = self._queue_path.read_text(encoding="utf-8").strip().splitlines()
            for line in lines[-_MAX_QUEUE_SIZE:]:
                try:
                    self._pending_queue.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.warning("Failed to load alert queue: %s", exc)

    def _save_pending_queue(self) -> None:
        """Сохранение очереди алертов в файл."""
        try:
            self._queue_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._queue_path, "w", encoding="utf-8") as fh:
                for item in self._pending_queue:
                    fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("Failed to save alert queue: %s", exc)

    @staticmethod
    def _sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
        """Удаляет чувствительные поля перед экспортом наружу (без мутации оригинала)."""
        result = copy.deepcopy(payload)
        try:
            context = result.get("context")
            if isinstance(context, dict):
                proc = context.get("process")
                if isinstance(proc, dict) and "environ" in proc:
                    proc.pop("environ", None)
        except Exception:
            return result
        return result

    def _build_syslog_handler(self, address: Any) -> SysLogHandler | None:
        try:
            if isinstance(address, str) and address.startswith("/"):
                return SysLogHandler(address=address, facility=self._syslog_facility)
            if isinstance(address, (list, tuple)) and len(address) == 2:
                host = str(address[0])
                port = int(address[1])
                return SysLogHandler(address=(host, port), facility=self._syslog_facility)
            host = "127.0.0.1"
            port = 514
            return SysLogHandler(address=(host, port), facility=self._syslog_facility)
        except Exception as exc:
            logger.error("Syslog handler init failed: %s", exc)
            return None

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import logging.config
import os
import signal
import sys
from pathlib import Path

import yaml

from phantom.core.config import get_config, validate_config_for_daemon
from phantom.core.control_plane import ControlPlane
from phantom.core.orchestrator import create_orchestrator
from phantom.core.traps import TrapRegistry
from phantom.factory.manager import TrapFactory
from phantom.sensors.manager import SensorManager
from phantom.factory.rotation import TrapRotator
from phantom.telemetry.precapture import get_precapture_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
)
logger = logging.getLogger("phantom.main")


def setup_logging(config_path: str | None = None) -> None:
    """Настройка логирования из YAML-файла. Ищет по стандартным путям если не указан явно."""
    if config_path:
        path = Path(config_path)
    else:
        # Стандартные пути поиска конфига логирования
        candidates = [
            Path("/etc/phantom/logging.yaml"),
            Path("config/logging.yaml"),
        ]
        path = next((p for p in candidates if p.exists()), None)  # type: ignore[assignment]
    if path is None or not path.exists():
        logger.warning("Logging config not found, using basicConfig")
        return
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        logging.config.dictConfig(data)
    except Exception as exc:
        logger.error("Failed to configure logging: %s", exc)


from typing import Any  # noqa: E402


async def _start_asgi_server(
    bind: str,
    port: int,
    api_cfg: dict,
    api_role_keys: dict[str, str],
    sensor_manager: Any,
    precapture: Any,
    orchestrator: Any,
    control: Any,
) -> Any:
    """Запуск ASGI-сервера (uvicorn + starlette)."""
    from phantom.api.asgi_app import create_asgi_app
    from phantom.api.auth import get_jwt_provider

    jwt_provider = get_jwt_provider()
    rate_limit = int(api_cfg.get("rate_limit_per_minute", 60))

    app = create_asgi_app(
        health_provider=lambda: {
            "status": "ok" if not sensor_manager.health.degraded else "degraded",
            "sensor_mode": sensor_manager.mode,
            "sensor_degraded": sensor_manager.health.degraded,
            "sensor_reason": sensor_manager.health.reason,
            "precapture": precapture.status(),
            "orchestrator": orchestrator.stats,
        },
        control=control,
        security_mode=str(api_cfg.get("security_mode", "api_key")),
        api_key=os.getenv(str(api_cfg.get("api_key_env", "PHANTOM_API_KEY"))),
        api_keys=api_role_keys,
        jwt_provider=jwt_provider,
        rate_limit_per_minute=rate_limit,
    )

    import uvicorn

    ssl_certfile = api_cfg.get("tls_cert")
    ssl_keyfile = api_cfg.get("tls_key")
    config = uvicorn.Config(
        app,
        host=bind,
        port=port,
        log_level="warning",
        ssl_certfile=ssl_certfile if ssl_certfile else None,
        ssl_keyfile=ssl_keyfile if ssl_keyfile else None,
    )
    server = uvicorn.Server(config)
    # Запускаем uvicorn в фоновой задаче
    asyncio.create_task(server.serve())
    logger.info("ASGI server started on %s:%s (TLS=%s)", bind, port, bool(ssl_certfile))
    return server


def _load_api_role_keys(api_cfg: dict[str, object]) -> dict[str, str]:
    keys: dict[str, str] = {}
    raw = api_cfg.get("keys", [])
    if not isinstance(raw, list):
        return keys
    for item in raw:
        if not isinstance(item, dict):
            continue
        env_name = str(item.get("env", "")).strip()
        role = str(item.get("role", "viewer")).strip().lower() or "viewer"
        if not env_name:
            continue
        token = os.getenv(env_name, "").strip()
        if not token:
            continue
        keys[token] = role
    return keys


def _api_cfg_fingerprint(api_cfg: dict[str, object], api_role_keys: dict[str, str]) -> str:
    """Хэш конфигурации API (включая секреты из ENV) для hot-reload."""
    api_key_env = str(api_cfg.get("api_key_env", "PHANTOM_API_KEY"))
    payload = {
        "security_mode": str(api_cfg.get("security_mode", "api_key")),
        "api_key": os.getenv(api_key_env, ""),
        "api_keys": api_role_keys,
        "jwt_secret": os.getenv("PHANTOM_JWT_SECRET", ""),
        "tls_cert": api_cfg.get("tls_cert"),
        "tls_key": api_cfg.get("tls_key"),
        "rate_limit_per_minute": int(api_cfg.get("rate_limit_per_minute", 60)),
    }
    packed = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(packed).hexdigest()


async def _async_main() -> int:
    setup_logging()
    logger.info("Starting Phantom Files Daemon v1.0.0")

    try:
        cfg = get_config()
        validate_config_for_daemon()
    except Exception as exc:
        logger.critical("Config load failed: %s", exc)
        return 1

    try:
        factory = TrapFactory(dict(cfg))
        summary = factory.deploy_traps()
    except Exception as exc:
        logger.critical("Trap deployment failed: %s", exc)
        return 1

    if summary.get("deployed", 0) == 0:
        logger.critical("No traps deployed; fail-close startup refused")
        return 1

    registry_file = summary.get("registry")
    if not registry_file:
        logger.critical("Trap registry file not created")
        return 1
    traps_root = str(cfg.get("paths", {}).get("traps_dir", "/var/lib/phantom/traps"))
    trap_registry = TrapRegistry.from_json(str(registry_file), expected_root=traps_root)

    raw_cfg = dict(cfg)
    # sensor manager starts first so orchestrator receives degraded status
    orchestrator = create_orchestrator(sensor_degraded=False)
    await orchestrator.start()
    control = ControlPlane(asyncio.get_running_loop())
    await control.initialize()
    orchestrator.subscribe_decisions(control.on_decision)

    sensor_manager = SensorManager(
        raw_cfg,
        callback=orchestrator.handle_event,
        permission_callback=orchestrator.pre_authorize,
        trap_registry=trap_registry,
        loop=asyncio.get_running_loop(),
    )
    precapture = get_precapture_manager(raw_cfg)
    precapture.start()

    # Ротация ловушек по таймеру
    rotator = TrapRotator(
        trap_registry=trap_registry,
        deploy_callback=lambda msg: logger.info("Rotation: %s", msg),
        config=dict(raw_cfg.get("rotation", {})),
    )
    rotator.start(loop=asyncio.get_running_loop())

    api_server: Any = None  # uvicorn.Server или None
    api_cfg = dict(raw_cfg.get("api", {}))
    api_role_keys = _load_api_role_keys(api_cfg)
    api_cfg_fingerprint = _api_cfg_fingerprint(api_cfg, api_role_keys)
    api_bind = str(api_cfg.get("bind", "127.0.0.1"))
    api_port = int(api_cfg.get("port", 8787))

    stop_event = asyncio.Event()
    reload_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGHUP, reload_event.set)
        loop.add_signal_handler(signal.SIGTERM, stop_event.set)
        loop.add_signal_handler(signal.SIGINT, stop_event.set)
    except NotImplementedError:
        pass

    try:
        sensor_manager.start()
        sensor_health = sensor_manager.health
        if sensor_health.degraded:
            logger.critical("Sensor degraded: %s", sensor_health.reason)
        orchestrator.set_sensor_degraded(sensor_health.degraded)
        if bool(api_cfg.get("enabled", True)):
            api_server = await _start_asgi_server(
                api_bind, api_port, api_cfg, api_role_keys,
                sensor_manager, precapture, orchestrator, control,
            )
        logger.info("Phantom started. sensor_mode=%s", sensor_manager.mode)
        while not stop_event.is_set():
            reload_task = asyncio.create_task(reload_event.wait())
            stop_task = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait(
                {reload_task, stop_task},
                timeout=60,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if stop_event.is_set():
                logger.info("Stop signal received, shutting down gracefully")
                break
            if reload_event.is_set():
                reload_event.clear()
                logger.info("SIGHUP received: reloading traps and configuration cache")
                try:
                    re_cfg = get_config(reload=True)

                    # Атомарная подмена с дренажом:
                    # 1. Приостанавливаем старые сенсоры (дренаж очереди событий)
                    if hasattr(sensor_manager, "pause"):
                        sensor_manager.pause()
                    # 2. Ждём опустошения очереди оркестратора
                    try:
                        await asyncio.wait_for(
                            orchestrator._event_queue.join(), timeout=5.0
                        )
                    except asyncio.TimeoutError:
                        logger.warning("Drain timeout: proceeding with reload")

                    # 3. Развёртываем ловушки
                    re_factory = TrapFactory(dict(re_cfg))
                    re_summary = re_factory.deploy_traps()
                    if re_summary.get("registry"):
                        trap_registry.reload_from_json(str(re_summary["registry"]))
                    await orchestrator.reload_settings(dict(re_cfg))
                    precapture.reload(dict(re_cfg))

                    # 4. Запускаем новые сенсоры
                    new_sensor_manager = SensorManager(
                        dict(re_cfg),
                        callback=orchestrator.handle_event,
                        permission_callback=orchestrator.pre_authorize,
                        trap_registry=trap_registry,
                        loop=asyncio.get_running_loop(),
                    )
                    new_sensor_manager.start()
                    # 5. Останавливаем старые сенсоры
                    old_sensor_manager = sensor_manager
                    sensor_manager = new_sensor_manager
                    old_sensor_manager.stop()

                    sensor_health = sensor_manager.health
                    orchestrator.set_sensor_degraded(sensor_health.degraded)
                    if sensor_health.degraded:
                        logger.critical("Sensor degraded after reload: %s", sensor_health.reason)

                    # Перезапуск ротатора с новой конфигурацией
                    rotator.stop()
                    rotator = TrapRotator(
                        trap_registry=trap_registry,
                        deploy_callback=lambda msg: logger.info("Rotation: %s", msg),
                        config=dict(re_cfg.get("rotation", {})),
                    )
                    rotator.start(loop=asyncio.get_running_loop())

                    # Перезапуск ASGI-сервера при изменении конфигурации
                    re_api_cfg = dict(re_cfg.get("api", {}))
                    re_enabled = bool(re_api_cfg.get("enabled", True))
                    re_bind = str(re_api_cfg.get("bind", "127.0.0.1"))
                    re_port = int(re_api_cfg.get("port", 8787))
                    re_api_keys = _load_api_role_keys(re_api_cfg)
                    re_api_fingerprint = _api_cfg_fingerprint(re_api_cfg, re_api_keys)

                    if api_server is not None and not re_enabled:
                        api_server.should_exit = True
                        api_server = None
                    elif re_enabled and (
                        api_server is None
                        or re_bind != api_bind
                        or re_port != api_port
                        or re_api_fingerprint != api_cfg_fingerprint
                    ):
                        if api_server is not None:
                            api_server.should_exit = True
                        api_server = await _start_asgi_server(
                            re_bind, re_port, re_api_cfg, re_api_keys,
                            sensor_manager, precapture, orchestrator, control,
                        )
                        api_bind = re_bind
                        api_port = re_port
                        api_cfg_fingerprint = re_api_fingerprint
                    logger.info("Reload deployment complete: %s", re_summary)
                except Exception as exc:
                    logger.error("Hot reload failed: %s", exc)
    except Exception as exc:
        logger.critical("Runtime error: %s", exc)
        return 1
    finally:
        if api_server is not None:
            api_server.should_exit = True
        rotator.stop()
        precapture.stop()
        sensor_manager.stop()
        await orchestrator.stop()
        logger.info("Phantom stopped")

    return 0


def run() -> None:
    rc = asyncio.run(_async_main())
    sys.exit(rc)


if __name__ == "__main__":
    run()

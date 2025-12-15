import os
import sys
import time
import logging
import logging.config
import yaml
from typing import Dict, Any

# --- Импорты модулей проекта ---
# Мы импортируем классы, а не функции, чтобы было понятно,
# из какого модуля что берется.
from phantom.core.config import load_config
from phantom.core.orchestrator import Orchestrator
from phantom.factory.manager import TrapFactory
from phantom.sensors.inotify import InotifySensor

# Инициализируем корневой логгер, чтобы видеть сообщения до загрузки конфига
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("PhantomDaemon")

def setup_logging(config_path: str = "config/logging.yaml"):
    """
    Настраивает систему логирования на основе YAML-конфига.
    """
    try:
        with open(config_path, 'rt') as f:
            log_config = yaml.safe_load(f.read())
        logging.config.dictConfig(log_config)
        logger.info("✅ Logging system configured successfully from YAML.")
    except Exception as e:
        logger.error(f"🔥 Failed to configure logging from {config_path}: {e}. Using basic config.")

def get_system_context() -> Dict[str, Any]:
    """
    Собирает базовый системный контекст (кто и где запускает).
    Эта функция дублирует логику из TrapFactory, чтобы контекст
    был доступен на самом верхнем уровне.
    """
    import socket
    import getpass
    try:
        user = os.getlogin()
    except OSError:
        user = getpass.getuser()
    
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
        
    return {"host": host, "user": user}

def run():
    """
    Главная точка входа (Entry Point) для демона Phantom Files.
    """
    logger.info("========================================")
    logger.info("👻 Initializing Phantom Files Daemon...")
    logger.info("========================================")

    # 1. Настройка логирования из файла
    setup_logging()

    # 2. Загрузка основной конфигурации
    try:
        config = load_config("config/phantom.yaml")
    except FileNotFoundError:
        logger.critical("🔥 Main configuration file 'config/phantom.yaml' not found. Exiting.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"🔥 Error loading configuration: {e}. Exiting.")
        sys.exit(1)

    # 3. Развертывание ловушек
    # Мы передаем в TrapFactory основной конфиг.
    # Системный контекст (user@host) он соберет сам внутри.
    try:
        factory = TrapFactory(config)
        summary = factory.deploy_traps()
        
        # --- ПРОВЕРКА РЕЗУЛЬТАТА (Фикс №3) ---
        # Если ни одна ловушка не была развернута, нет смысла продолжать работу.
        if summary.get("deployed", 0) == 0:
            logger.critical("🔥 No traps were deployed! Check manifest permissions or paths. Exiting.")
            sys.exit(1)

    except Exception as e:
        logger.critical(f"🔥 A critical error occurred during trap deployment: {e}")
        sys.exit(1)

    # 4. Инициализация ядра (Оркестратора)
    # Оркестратор будет принимать события от сенсоров и запускать Sandbox.
    orchestrator = Orchestrator(config)

    # 5. Запуск сенсоров
    # В MVP используется только 'inotify', но архитектура готова к расширению.
    sensor = InotifySensor(config, callback=orchestrator.handle_event)
    
    try:
        sensor.start()
        logger.info("✅ System is active. Monitoring for threats...")
        
        # Бесконечный цикл, чтобы демон не завершался.
        # В реальности, в systemd-сервисе это может быть не нужно,
        # но для ручного запуска и отладки - обязательно.
        while True:
            time.sleep(3600) # "Спим" большими интервалами для экономии CPU

    except KeyboardInterrupt:
        # Корректная обработка Ctrl+C
        logger.info("🛑 SIGINT received. Shutting down gracefully...")
    except Exception as e:
        logger.critical(f"🔥 A critical error occurred in the main loop: {e}")
    finally:
        # Гарантированно останавливаем мониторинг перед выходом
        sensor.stop()
        logger.info("👋 Phantom Daemon has been shut down.")
        sys.exit(0)

if __name__ == "__main__":
    # Эта строка позволяет запускать файл напрямую: python -m phantom.main
    run()
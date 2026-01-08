import os
import socket
import getpass
import logging
import yaml
from datetime import datetime
from typing import Optional, Dict, Any
from .generators import ContentGenerator

logger = logging.getLogger("Factory.Manager")

class TrapFactory:
    """
    Оркестратор развертывания файлов-ловушек (Honeytokens).

    Этот класс управляет полным жизненным циклом создания ловушек:
    1. Загружает конфигурацию и манифест задач.
    2. Собирает контекст системы (кто и где запускает).
    3. Инициализирует генератор контента.
    4. Выполняет итерацию по задачам и размещает файлы на диске.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Инициализирует фабрику ловушек.

        Args:
            config (Dict[str, Any]): Словарь конфигурации, содержащий секцию 'paths'
                                     с путями к директориям и манифесту.
        """
        self.config = config
        self.traps_dir = config["paths"]["traps_dir"]
        self.templates_dir = config["paths"]["templates"]
        self.manifest_path = config["paths"]["manifest"]
        
        # Инициализация генератора контента (Faker + Jinja2)
        self.generator = ContentGenerator()

        # Создаем единый профиль "жертвы" (Shared Context), 
        # чтобы данные во всех ловушках (имя админа, пароли) совпадали.
        self.base_context = self.generator.create_base_context()

        # Собираем системный контекст (реальный пользователь и хост)
        self.system_context = self._get_system_context()

    def _get_system_context(self) -> Dict[str, Any]:
        """
        Собирает информацию о текущем пользователе ОС и имени хоста.

        Использует механизм fallback: сначала пытается получить пользователя
        через терминал (os.getlogin), если не удается — через переменные
        окружения (getpass).

        Returns:
            Dict[str, Any]: Словарь с ключами 'host' и 'user'.
        """
        try:
            user = os.getlogin()
        except OSError:
            # Если скрипт запущен без терминала (например, через systemd или cron)
            user = getpass.getuser()
        
        try:
            host = socket.gethostname()
        except Exception:
            host = "unknown"
            
        return {"host": host, "user": user}

    def _load_trap_tasks(self) -> list:
        """
        Загружает список задач на генерацию из YAML-манифеста.

        Returns:
            list: Список словарей с параметрами ловушек. 
                  Возвращает пустой список в случае ошибки ввода-вывода или парсинга.
        """
        if not os.path.exists(self.manifest_path):
            logger.error(f"Manifest file not found at: {self.manifest_path}")
            return []
            
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                # Безопасная загрузка YAML и извлечение ключа 'traps'
                return yaml.safe_load(f).get("traps", [])
        except Exception as e:
            logger.error(f"Failed to load manifest {self.manifest_path}: {e}")
            return []

    def deploy_traps(self) -> Dict[str, Any]:
        """
        Основной метод: разворачивает набор ловушек согласно манифесту.

        Создает целевые директории, перебирает задачи и делегирует создание
        файлов классу ContentGenerator в зависимости от формата (text/binary).

        Returns:
            Dict[str, Any]: Отчет о результатах, содержащий количество 
                            развернутых ловушек ('deployed') и общее число задач ('total').
        """

        logger.info(f"Daemon initialized (PID: {os.getpid()}). User context: {self.system_context['user']}@{self.system_context['host']}")
        logger.info("Starting honeytoken deployment sequence...")

        # Гарантируем существование целевой папки
        os.makedirs(self.traps_dir, exist_ok=True)
        
        tasks = self._load_trap_tasks()
        
        if not tasks:
            logger.warning("No trap tasks found in manifest. Nothing to deploy.")
            return {"deployed": 0, "total": 0}

        success = 0
        for task in tasks:
            tpl_path = os.path.join(self.templates_dir, task["template"])
            out_path = os.path.join(self.traps_dir, task["output"])

            logger.info(f"[Generator] Processing artifact ID: {task.get('id', 'N/A')} | Template: {task['template']}")

            # Пропуск задачи, если шаблон отсутствует физически
            if not os.path.exists(tpl_path):
                logger.error(f"[Generator] Template missing: {tpl_path}. Skipping.")
                continue

            # Подготовка метаданных для логирования и возможной аналитики
            metadata = {
                "category": task.get("category"),
                "priority": task.get("priority"),
                "trap_id": task.get("id"),
            }

            # Выбор стратегии генерации
            if task.get("format") == "text":
                # Для текстовых файлов создаем уникальный контекст (версии, даты)
                # на основе базового профиля
                trap_ctx = self.generator.create_trap_context(self.base_context)
                self.generator.create_text_trap(tpl_path, out_path, trap_ctx, metadata=metadata)
            else: 
                # Для бинарных файлов (docx, pdf) используем копирование с уникализацией
                self.generator.create_binary_trap(tpl_path, out_path, metadata=metadata)
            
            success += 1

        logger.info(f"Deployment sequence completed. Active sensors: {success}/{len(tasks)}.")
        return {"deployed": success, "total": len(tasks)}

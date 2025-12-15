import os
import socket
import getpass
import logging
import yaml  # <-- ИЗМЕНЕНИЕ: Добавлен импорт для чтения YAML
from typing import Optional, Dict, Any
from .generators import ContentGenerator

logger = logging.getLogger("Factory.Manager")


class TrapFactory:
    """
    Оркестратор развертывания ловушек. Отвечает за:
      - Загрузку манифеста ловушек из YAML.
      - Сбор системного контекста (user@host) для метаданных.
      - Создание единого профиля "жертвы" (base_context).
      - Передачу задач и контекста в ContentGenerator.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.traps_dir = config["paths"]["traps_dir"]
        self.templates_dir = config["paths"]["templates"]
        
        # --- ИЗМЕНЕНИЕ: Путь к манифесту теперь используется в _load_trap_tasks ---
        self.manifest_path = config["paths"]["manifest"]

        # Единый профиль "жертвы", который будет общим для всех ловушек
        self.base_context = ContentGenerator.create_base_context()

        # Системный контекст (для логов и сенсоров)
        self.system_context = self._get_system_context()

    def _get_system_context(self) -> Dict[str, Any]:
        # --- ИЗМЕНЕНИЕ: Улучшено определение пользователя ---
        """
        Собирает информацию о текущем пользователе и хосте.
        os.getlogin() более надежен, так как привязан к терминалу сессии.
        getpass.getuser() используется как fallback, если терминала нет (например, в systemd).
        """
        try:
            # Пытаемся получить пользователя из терминала
            user = os.getlogin()
        except OSError:
            # Если не получилось, используем переменные окружения
            user = getpass.getuser()
            
        try:
            host = socket.gethostname()
        except Exception:
            host = "unknown"
            
        return {"host": host, "user": user, "group": "production"}

    def _load_trap_tasks(self) -> list:
        # --- НОВЫЙ МЕТОД: Убираем хардкод ---
        """Загружает список задач из YAML-манифеста."""
        if not os.path.exists(self.manifest_path):
            logger.error(f"Manifest file not found at: {self.manifest_path}")
            return []
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = yaml.safe_load(f)
            
            tasks = manifest_data.get("traps", [])
            if not isinstance(tasks, list):
                logger.error("'traps' key in manifest is not a list.")
                return []
            
            return tasks
        except Exception as e:
            logger.error(f"Failed to load or parse manifest {self.manifest_path}: {e}")
            return []

    def deploy_traps(self, target_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Разворачивает набор ловушек согласно манифесту.
        Возвращает summary с количеством развернутых ловушек.
        """
        logger.info("🏭 Trap Factory starting deployment...")

        context = target_context or self.system_context
        logger.info(f"📍 Deployment context: {context.get('user', 'n/a')}@{context.get('host', 'n/a')}")

        os.makedirs(self.traps_dir, exist_ok=True)

        # --- ИЗМЕНЕНИЕ: Задачи теперь читаются из файла ---
        tasks = self._load_trap_tasks()
        if not tasks:
            logger.warning("No trap tasks found in manifest. Nothing to deploy.")
            return {"deployed": 0, "total": 0, "context": context}

        success = 0
        for task in tasks:
            tpl_path = os.path.join(self.templates_dir, task["template"])
            out_path = os.path.join(self.traps_dir, task["output"])

            if not os.path.exists(tpl_path):
                logger.warning(f"⚠️ Missing template: {task['template']} for trap '{task.get('id', 'N/A')}'. Skipping.")
                continue

            # Метаданные для логирования и сенсоров
            metadata = {
                "user": context.get("user"),
                "host": context.get("host"),
                "group": context.get("group"),
                "category": task.get("category"),
                "priority": task.get("priority"),
                "trap_id": task.get("id"),
            }

            if task["format"] == "text":
                # Обогащаем базовый контекст уникальными данными для этой ловушки
                trap_ctx = ContentGenerator.enrich_context(self.base_context, task["template"])
                ContentGenerator.create_text_trap(tpl_path, out_path, trap_ctx, metadata=metadata)
            else:
                ContentGenerator.create_binary_trap(tpl_path, out_path, metadata=metadata)

            success += 1

        logger.info(f"✅ Trap deployment finished: {success}/{len(tasks)} traps are active.")
        return {"deployed": success, "total": len(tasks), "context": context}

    def get_trap_info(self) -> Dict[str, Any]:
        """
        Возвращает базовую информацию о развернутых ловушках (имена, размеры, mtime).
        Полезно для мониторинга/healthcheck.
        """
        info = []
        if not os.path.exists(self.traps_dir):
            return {"count": 0, "traps": info, "context": self.system_context}

        try:
            for fn in os.listdir(self.traps_dir):
                fp = os.path.join(self.traps_dir, fn)
                if os.path.isfile(fp):
                    st = os.stat(fp)
                    info.append({"filename": fn, "size_bytes": st.st_size, "mtime_unix": st.st_mtime})
        except Exception as e:
            logger.error(f"Failed to get trap info from {self.traps_dir}: {e}")

        return {"count": len(info), "traps": info, "context": self.system_context}
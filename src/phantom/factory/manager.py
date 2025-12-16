import os
import socket
import getpass
import logging
import yaml
from typing import Optional, Dict, Any
from .generators import ContentGenerator

logger = logging.getLogger("Factory.Manager")

class TrapFactory:
    """
    Оркестратор развертывания ловушек.
    - Загружает манифест.
    - Инициализирует генератор с нужной локалью.
    - Управляет процессом создания ловушек.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.traps_dir = config["paths"]["traps_dir"]
        self.templates_dir = config["paths"]["templates"]
        self.manifest_path = config["paths"]["manifest"]
        
        self.generator = ContentGenerator()

        # Создаем единый профиль "жертвы"
        self.base_context = self.generator.create_base_context()

        # Собираем системный контекст
        self.system_context = self._get_system_context()

    def _get_system_context(self) -> Dict[str, Any]:
        """Собирает информацию о текущем пользователе и хосте."""
        try:
            user = os.getlogin()
        except OSError:
            user = getpass.getuser()
        try:
            host = socket.gethostname()
        except Exception:
            host = "unknown"
        return {"host": host, "user": user}

    def _load_trap_tasks(self) -> list:
        """Загружает список задач из YAML-манифеста."""
        if not os.path.exists(self.manifest_path):
            logger.error(f"Manifest file not found at: {self.manifest_path}")
            return []
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f).get("traps", [])
        except Exception as e:
            logger.error(f"Failed to load manifest {self.manifest_path}: {e}")
            return []

    def deploy_traps(self) -> Dict[str, Any]:
        """Разворачивает набор ловушек согласно манифесту."""
        logger.info("🏭 Trap Factory starting deployment...")
        logger.info(f"📍 Deployment context: {self.system_context['user']}@{self.system_context['host']}")

        os.makedirs(self.traps_dir, exist_ok=True)
        tasks = self._load_trap_tasks()
        
        if not tasks:
            logger.warning("No trap tasks found in manifest. Nothing to deploy.")
            return {"deployed": 0, "total": 0}

        success = 0
        for task in tasks:
            tpl_path = os.path.join(self.templates_dir, task["template"])
            out_path = os.path.join(self.traps_dir, task["output"])

            if not os.path.exists(tpl_path):
                logger.warning(f"⚠️ Missing template: {task['template']}. Skipping.")
                continue

            metadata = {
                "category": task.get("category"),
                "priority": task.get("priority"),
                "trap_id": task.get("id"),
            }

            if task.get("format") == "text":
                trap_ctx = self.generator.create_trap_context(self.base_context)
                self.generator.create_text_trap(tpl_path, out_path, trap_ctx, metadata=metadata)
            else: 
                self.generator.create_binary_trap(tpl_path, out_path, metadata=metadata)
            success += 1

        logger.info(f"✅ Trap deployment finished: {success}/{len(tasks)} traps are active.")
        return {"deployed": success, "total": len(tasks)}
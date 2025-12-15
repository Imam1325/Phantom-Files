import os
import copy
import shutil
import random
import logging
from typing import Optional, Dict, Any
from jinja2 import Template
from faker import Faker
from .metadata import stomp_timestamp

logger = logging.getLogger("Factory.Gen")

class ContentGenerator:
    """
    Генератор контента для ловушек.
    - Использует Faker для создания правдоподобных данных.
    - Поддерживает локализацию (ru_RU, en_US).
    - Использует Jinja2 для рендеринга шаблонов.
    """
    
    def __init__(self, locale: str = "en_US"):
        """
        Инициализирует генератор с заданной локалью.
        """
        try:
            self.fake = Faker(locale)
        except Exception:
            logger.warning(f"Locale '{locale}' not found for Faker, falling back to 'en_US'.")
            self.fake = Faker("en_US")

    def create_base_context(self) -> Dict[str, Any]:
        """
        Создает базовый профиль "жертвы", который будет общим для всех ловушек.
        """
        return {
            # --- Персональные данные ---
            "admin_name": self.fake.name(),
            "admin_email": self.fake.company_email(),
            "company": self.fake.company(),
            
            # --- Технические данные ---
            "db_host": f"db-prod-{self.fake.word()}.{self.fake.domain_name()}",
            "db_password": self.fake.password(length=14, special_chars=True),
            "aws_key": self.fake.pystr_format(string_format="????????????????"),
            "sentry_key": self.fake.hexify(text="^" * 32),
            "sentry_id": random.randint(10000, 99999),
        }
        
    def create_trap_context(self, base_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Добавляет в контекст "свежие" данные (дату, версию), которые должны
        быть уникальными для каждого файла.
        """
        ctx = copy.deepcopy(base_context)
        ctx.update({
            "version": f"v{random.randint(1,4)}.{random.randint(0,9)}.{random.randint(0,10)}",
            "iso_date": self.fake.iso8601(),
            "date": self.fake.date_this_year(),
        })
        return ctx

    def create_text_trap(
        self,
        template_path: str,
        output_path: str,
        context: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Рендерит текстовый шаблон с предоставленным контекстом.
        """
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = Template(f.read())

            content = template.render(context)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            stomp_timestamp(output_path)
            
            # Упрощенное логирование
            meta_str = f" [{metadata.get('category', 'N/A')}]" if metadata else ""
            logger.info(f"📄 Generated text trap: {os.path.basename(output_path)}{meta_str}")

        except Exception as exc:
            logger.error(f"Error generating text trap {output_path}: {exc}")

    def create_binary_trap(
        self,
        source_path: str,
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Копирует бинарный файл и подделывает ему время."""
        try:
            shutil.copy2(source_path, output_path)
            stomp_timestamp(output_path)

            meta_str = f" [{metadata.get('category', 'N/A')}]" if metadata else ""
            logger.info(f"📎 Deployed binary trap: {os.path.basename(output_path)}{meta_str}")

        except Exception as exc:
            logger.error(f"Error deploying binary trap {output_path}: {exc}")
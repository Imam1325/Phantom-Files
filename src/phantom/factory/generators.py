import os
import copy
import shutil
import random
import logging
import uuid
import zipfile
import base64
from typing import Optional, Dict, Any
from jinja2 import Template
from faker import Faker
from .metadata import stomp_timestamp

logger = logging.getLogger("Factory.Gen")

class ContentGenerator:
    """
    Генератор контента для ловушек.
    - Uses Faker for realistic data.
    - Supports localization (ru_RU, en_US).
    - Uses Jinja2 for text templates.
    - Implements Smart Watermarking for binary polymorphism.
    - Generates fake crypto-material (certs/keys).
    """
    
    def __init__(self):
            self.fake = Faker()

    def _generate_fake_cert_body(self, length: int = 1000) -> str:
        """
        Генерирует случайный Base64 блок, визуально похожий на тело сертификата (PEM).
        """
        random_bytes = os.urandom(length)
        b64_str = base64.b64encode(random_bytes).decode('utf-8')
        # Разбиваем на строки по 64 символа (стандарт PEM формата)
        return '\n'.join(b64_str[i:i+64] for i in range(0, len(b64_str), 64))

    def create_base_context(self) -> Dict[str, Any]:
        """
        Создает базовый профиль "жертвы" (Shared Context).
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
            "crm_ip": self.fake.ipv4_private(),

            # --- Криптография (для VPN и SSH) ---
            "ca_cert_body": self._generate_fake_cert_body(1200),
            "client_cert_body": self._generate_fake_cert_body(1000),
            "private_key_body": self._generate_fake_cert_body(1600),
        }
        
    def create_trap_context(self, base_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Добавляет уникальные данные (версию, дату) к базовому профилю.
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
        """Рендерит текстовый шаблон."""
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = Template(f.read())

            content = template.render(context)

            # --- ВАЖНО: Создаем папку, если её нет ---
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            stomp_timestamp(output_path)
            
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
        """
        Копирует бинарный файл и делает его полиморфным.
        """
        try:
            # --- ВАЖНО: Создаем папку, если её нет ---
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 1. Копируем файл
            shutil.copy2(source_path, output_path)
            
            # 2. Генерируем ID
            trap_id = metadata.get("trap_id", str(uuid.uuid4())) if metadata else str(uuid.uuid4())
            
            # 3. Применяем стратегию в зависимости от расширения
            if output_path.endswith(('.docx', '.xlsx', '.pptx', '.zip')):
                self._inject_zip_comment(output_path, trap_id)
            else:
                self._append_watermark(output_path, trap_id)

            # 4. Подделываем дату
            stomp_timestamp(output_path)

            meta_str = f" [{metadata.get('category', 'N/A')}]" if metadata else ""
            logger.info(f"📎 Deployed UNIQUE binary trap: {os.path.basename(output_path)}{meta_str}")

        except Exception as exc:
            logger.error(f"Error deploying binary trap {output_path}: {exc}")

    def _inject_zip_comment(self, filepath: str, trap_id: str):
        """Безопасная инъекция в ZIP-структуру (DOCX/XLSX)."""
        try:
            with zipfile.ZipFile(filepath, mode='a') as zf:
                zf.comment = f"PHANTOM_ID:{trap_id}".encode('utf-8')
        except zipfile.BadZipFile:
            self._append_watermark(filepath, trap_id)

    def _append_watermark(self, filepath: str, trap_id: str):
        """Дописывание данных в конец файла."""
        watermark = f"\n<!-- PHANTOM_TRAP_ID:{trap_id} -->".encode('utf-8')
        with open(filepath, "ab") as f:
            f.write(watermark)
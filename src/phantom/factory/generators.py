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

logger = logging.getLogger("Phantom.Generator")

class ContentGenerator:
    """
    Генератор контента для файлов-ловушек.

    Отвечает за создание реалистичного содержимого для текстовых и бинарных файлов.
    Использует библиотеку Faker для генерации данных, Jinja2 для шаблонизации
    и различные техники (Time Stomping, Watermarking) для повышения правдоподобности.
    """
    
    def __init__(self):
        """Инициализирует генератор с использованием стандартного английского Faker."""
        self.fake = Faker()

    def _generate_fake_cert_body(self, length: int = 1000) -> str:
        """
        Генерирует случайный Base64 блок, визуально имитирующий тело сертификата (PEM формат).

        Args:
            length (int): Длина генерируемого блока в байтах (до кодирования).

        Returns:
            str: Строка Base64, разбитая на линии по 64 символа (стандарт PEM).
        """
        random_bytes = os.urandom(length)
        b64_str = base64.b64encode(random_bytes).decode('utf-8')
        # Разбиваем на строки по 64 символа, как принято в сертификатах
        return '\n'.join(b64_str[i:i+64] for i in range(0, len(b64_str), 64))

    def create_base_context(self) -> Dict[str, Any]:
        """
        Создает базовый профиль "жертвы" (Shared Context).

        Эти данные (имя администратора, название компании, пароли) будут 
        использоваться во всех генерируемых файлах, создавая связную легенду.

        Returns:
            Dict[str, Any]: Словарь с общими данными для шаблонов.
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
            # Генерируем уникальные "ключи" для этой сессии развертывания
            "ca_cert_body": self._generate_fake_cert_body(1200),
            "client_cert_body": self._generate_fake_cert_body(1000),
            "private_key_body": self._generate_fake_cert_body(1600),
        }
        
    def create_trap_context(self, base_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Создает контекст для конкретного файла на основе базового.

        Добавляет уникальные для каждого файла данные (версия, дата изменения),
        чтобы файлы выглядели созданными в разное время, но одним человеком.

        Args:
            base_context (Dict[str, Any]): Общий профиль жертвы.

        Returns:
            Dict[str, Any]: Расширенный контекст для рендеринга шаблона.
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
        Генерирует текстовый файл-ловушку (JSON, YAML, ENV, и т.д.) из шаблона.

        1. Читает Jinja2 шаблон.
        2. Рендерит его с переданным контекстом.
        3. Сохраняет результат.
        4. Подделывает дату создания файла (Time Stomping).

        Args:
            template_path (str): Путь к файлу шаблона.
            output_path (str): Путь сохранения готовой ловушки.
            context (Dict[str, Any]): Данные для подстановки в шаблон.
            metadata (Optional[Dict]): Дополнительные данные для логирования.
        """
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = Template(f.read())

            content = template.render(context)

            # Гарантируем, что целевая директория существует (например, .aws/)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Применяем технику Time Stomping
            stomp_timestamp(output_path)
            
            meta_str = f" [{metadata.get('category', 'N/A')}]" if metadata else ""
            logger.debug(f"Rendered template: {os.path.basename(output_path)}")

        except Exception as exc:
            logger.error(f"Template render failed [{output_path}]: {exc}")

    def create_binary_trap(
        self,
        source_path: str,
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Создает бинарный файл-ловушку (DOCX, PDF, XLSX).

        Использует технику полиморфизма: копирует файл-шаблон и добавляет
        в него уникальный невидимый идентификатор (Watermark). Это меняет
        хеш-сумму файла, делая каждую копию уникальной для антивирусов.

        Args:
            source_path (str): Путь к "золотому образу" (исходному файлу).
            output_path (str): Путь сохранения ловушки.
            metadata (Optional[Dict]): Метаданные (включая trap_id для уникализации).
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 1. Копируем файл
            shutil.copy2(source_path, output_path)
            
            # 2. Генерируем уникальный ID для watermarking
            trap_id = metadata.get("trap_id", str(uuid.uuid4())) if metadata else str(uuid.uuid4())
            
            # 3. Применяем стратегию внедрения watermark в зависимости от типа файла
            if output_path.endswith(('.docx', '.xlsx', '.pptx', '.zip')):
                # Для ZIP-based форматов (Office) используем безопасную инъекцию в комментарий архива
                self._inject_zip_comment(output_path, trap_id)
            else:
                # Для остальных просто дописываем в конец файла
                self._append_watermark(output_path, trap_id)

            # 4. Подделываем дату создания
            stomp_timestamp(output_path)

            meta_str = f" [{metadata.get('category', 'N/A')}]" if metadata else ""
            logger.debug(f"Binary artifact cloned: {os.path.basename(output_path)}")

        except Exception as exc:
            logger.error(f"Binary generation failed [{output_path}]: {exc}")

    def _inject_zip_comment(self, filepath: str, trap_id: str):
        """
        Внедряет ID ловушки в комментарий ZIP-архива.
        Это легальный способ добавить данные в DOCX/XLSX, не нарушая их структуру.
        """
        try:
            with zipfile.ZipFile(filepath, mode='a') as zf:
                # Комментарий в ZIP должен быть в байтах
                zf.comment = f"PHANTOM_ID:{trap_id}".encode('utf-8')
        except zipfile.BadZipFile:
            # Если файл битый, используем fallback стратегию
            self._append_watermark(filepath, trap_id)

    def _append_watermark(self, filepath: str, trap_id: str):
        """
        Дописывает данные в конец файла.
        Работает для PDF и других форматов, которые игнорируют мусор в конце (EOF).
        """
        watermark = f"\n<!-- PHANTOM_TRAP_ID:{trap_id} -->".encode('utf-8')
        with open(filepath, "ab") as f:
            f.write(watermark)

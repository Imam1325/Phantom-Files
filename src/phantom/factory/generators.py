import os
import copy
import shutil
import random
import logging
import uuid
import base64
from typing import Optional, Dict, Any
from jinja2 import Template
from faker import Faker
from .metadata import stomp_timestamp

fake = Faker()
logger = logging.getLogger("Factory.Gen")


class ContentGenerator:
    """
    Stateless генератор контента для ловушек.
    - fingerprint детерминированный и скрытный (UUIDv5 -> base64, sanitized)
    - fingerprint НЕ вставляется в явные поля вида 'trap_id' или timestamp
    - fingerprint "растворяется" в правдоподобных полях (version patch, db_host suffix, aws_key tail)
    """

    @staticmethod
    def _generate_fingerprint(template_name: str) -> str:
        """
        Детерминированный короткий fingerprint для шаблона.
        Возвращает строку из 6-8 безопасных символов (A-Z0-9).
        """
        ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
        t_uuid = uuid.uuid5(ns, template_name)
        encoded = base64.b64encode(t_uuid.bytes).decode("ascii")
        # Сanitise: оставить только alnum и взять первые 6 символов
        cleaned = "".join(c for c in encoded if c.isalnum())[:6]
        # Если вдруг короткая — дополнить цифрами
        if len(cleaned) < 6:
            cleaned = (cleaned + str(random.randint(1000, 9999)))[:6]
        return cleaned

    @staticmethod
    def _derive_patch_from_fp(fp: str) -> int:
        """
        Детерминированная функция fp -> patch (0..9).
        Не используем hash() (нестабилен между интерпретаторами).
        """
        # Простая, стабильная и детерминированная агрегация
        s = 0
        for ch in fp:
            s = (s * 31 + ord(ch)) & 0xFFFFFFFF
        return s % 10

    @staticmethod
    def _derive_host_suffix(fp: str) -> str:
        # Возьмём первые 3 алфанумерные символа fp в нижнем регистре
        suffix = "".join(c for c in fp if c.isalnum())[:3].lower()
        if len(suffix) < 3:
            suffix = suffix.ljust(3, "x")
        return suffix

    @staticmethod
    def _derive_aws_tail(fp: str) -> str:
        # Возьмём 4 символа fp в верхнем регистре для tail
        tail = "".join(c for c in fp.upper() if c.isalnum())[:4]
        if len(tail) < 4:
            tail = (tail + "0" * 4)[:4]
        return tail

    @staticmethod
    def create_base_context() -> Dict[str, Any]:
        """
        Базовый профиль "жертвы" (SMB). Manager создаёт один экземпляр и передаёт его.
        """
        return {
            "company": fake.company(),
            "admin_name": fake.name(),
            "admin_email": fake.company_email(),
            # Хост в базе контекста — без fingerprint суффикса
            "db_host": f"db-prod-{fake.word()}.{fake.domain_name()}",
            "db_password": fake.password(length=14),
            # aws_key базовая часть будет дополнена fingerprint-частью при enrich
            "aws_key_base": fake.bothify(text="????????????").upper(),
            "sentry_key": fake.hexify(text="^" * 32),
            "sentry_id": random.randint(10000, 99999),
            "crm_ip": fake.ipv4_private(),
        }

    @staticmethod
    def enrich_context(base_context: Dict[str, Any], template_name: str) -> Dict[str, Any]:
        """
        Создаёт контекст для конкретного шаблона.
        - добавляет version с детерминированной patch
        - модифицирует db_host (суффикс)
        - формирует aws_key как base + tail (tail от fingerprint)
        """
        fp = ContentGenerator._generate_fingerprint(template_name)
        patch = ContentGenerator._derive_patch_from_fp(fp)
        host_suffix = ContentGenerator._derive_host_suffix(fp)
        aws_tail = ContentGenerator._derive_aws_tail(fp)

        ctx = copy.deepcopy(base_context)  # shallow copy

        # realistic version where last number subtly correlated with fingerprint
        ctx["version"] = f"v{random.randint(1,4)}.{random.randint(0,9)}.{patch}"

        # dates
        ctx["iso_date"] = fake.iso8601()
        ctx["date"] = fake.date_this_year()

        # patched db_host (keep base word but add suffix)
        # preserve existing base db_host structure if present
        base_db_host = base_context.get("db_host", f"db-prod-{fake.word()}.{fake.domain_name()}")
        # insert suffix before first dot
        if "." in base_db_host:
            left, right = base_db_host.split(".", 1)
            left = f"{left}-{host_suffix}"
            ctx["db_host"] = f"{left}.{right}"
        else:
            ctx["db_host"] = f"{base_db_host}-{host_suffix}"

        # aws key: combine base and tail (masked, looks natural)
        aws_base = base_context.get("aws_key_base", fake.bothify(text="????????????").upper())
        ctx["aws_key"] = (aws_base + aws_tail)[:16]

        # other fields (keep or override)
        ctx["sentry_key"] = base_context.get("sentry_key")
        ctx["sentry_id"] = base_context.get("sentry_id")
        ctx["admin_name"] = base_context.get("admin_name")
        ctx["admin_email"] = base_context.get("admin_email")
        ctx["db_password"] = base_context.get("db_password")
        ctx["crm_ip"] = base_context.get("crm_ip")

        # Internal: do NOT include fp in file content. But include subtle internal fields for templates that expect them.
        # Keep them prefixed with underscore to reduce chance of accidental exposure.
        ctx["_internal_build_tail"] = aws_tail  # short, harmless internal hint if template uses it
        ctx["_internal_fp_stub"] = fp[:4]  # very short stub; optional to use in templates

        return ctx

    @classmethod
    def create_text_trap(
        cls,
        template_path: str,
        output_path: str,
        context: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Render text template with provided context.
        metadata is used only for logging / sensor hints and is NOT injected into main fields unless explicitly desired.
        """
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                raw = f.read()

            template = Template(raw)
            # Note: templates can still use '_internal_*' fields if you want subtle markers
            content = template.render(context)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            stomp_timestamp(output_path)

            # Log with masked fingerprint info for internal correlation (do not expose full fp)
            fp_stub = context.get("_internal_fp_stub", "----")
            meta_str = ""
            if metadata:
                user = metadata.get("user", "any")
                host = metadata.get("host", "any")
                cat = metadata.get("category", "any")
                meta_str = f" [{user}@{host} | {cat}]"
            logger.info(f"📄 Text trap: {os.path.basename(output_path)} [fp:{fp_stub}]{meta_str}")

        except Exception as exc:
            logger.error(f"Error generating text trap {output_path}: {exc}")

    @staticmethod
    def create_binary_trap(
        source_path: str,
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            shutil.copy2(source_path, output_path)
            stomp_timestamp(output_path)

            meta_str = ""
            if metadata:
                user = metadata.get("user", "any")
                host = metadata.get("host", "any")
                cat = metadata.get("category", "any")
                meta_str = f" [{user}@{host} | {cat}]"

            logger.info(f"📎 Binary trap: {os.path.basename(output_path)}{meta_str}")

        except Exception as exc:
            logger.error(f"Error deploying binary trap {output_path}: {exc}")

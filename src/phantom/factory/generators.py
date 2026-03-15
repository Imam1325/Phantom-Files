"""
Генерация содержимого для файлов-ловушек.
"""

from __future__ import annotations

import base64
import copy
import logging
import os
import random
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

from faker import Faker
from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

from .metadata import stomp_timestamp

logger = logging.getLogger("phantom.factory.generator")


class ContentGenerator:
    def __init__(self, stomp_config: Optional[Dict[str, Any]] = None):
        self.fake = Faker()
        self.stomp_config = stomp_config
        self._jinja = SandboxedEnvironment(
            autoescape=False,
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _generate_fake_cert_body(self, length: int = 1000) -> str:
        random_bytes = os.urandom(length)
        b64 = base64.b64encode(random_bytes).decode("utf-8")
        return "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))

    def create_base_context(self) -> Dict[str, Any]:
        return {
            "admin_name": self.fake.name(),
            "admin_email": self.fake.company_email(),
            "company": self.fake.company(),
            "db_host": f"db-prod-{self.fake.word()}.{self.fake.domain_name()}",
            "db_password": self.fake.password(length=16, special_chars=True),
            "aws_key": self.fake.pystr_format(string_format="????????????????"),
            "sentry_key": self.fake.hexify(text="^" * 32),
            "sentry_id": random.randint(10000, 99999),
            "crm_ip": self.fake.ipv4_private(),
            "ca_cert_body": self._generate_fake_cert_body(1200),
            "client_cert_body": self._generate_fake_cert_body(1000),
            "private_key_body": self._generate_fake_cert_body(1600),
        }

    def create_trap_context(self, base_context: Dict[str, Any]) -> Dict[str, Any]:
        ctx = copy.deepcopy(base_context)
        ctx.update(
            {
                "version": f"v{random.randint(1,4)}.{random.randint(0,9)}.{random.randint(0,10)}",
                "iso_date": self.fake.iso8601(),
                "date": self.fake.date_this_year(),
            }
        )
        return ctx

    def create_text_trap(
        self,
        template_path: str,
        output_path: str,
        context: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        template_file = Path(template_path)
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            source = template_file.read_text(encoding="utf-8")
            template = self._jinja.from_string(source)
            content = template.render(context)
            out_file.write_text(content, encoding="utf-8")
            stomp_timestamp(str(out_file), config=self.stomp_config)
            logger.debug(
                "Rendered trap %s (%s)",
                out_file.name,
                metadata.get("trap_id", "unknown") if metadata else "unknown",
            )
        except Exception as exc:
            logger.error("Text trap render failed (%s): %s", out_file, exc)
            raise

    def create_binary_trap(
        self,
        source_path: str,
        output_path: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        src = Path(source_path)
        dst = Path(output_path)
        dst.parent.mkdir(parents=True, exist_ok=True)

        trap_id = metadata.get("trap_id", uuid.uuid4().hex) if metadata else uuid.uuid4().hex
        try:
            shutil.copy2(src, dst)
            if dst.suffix.lower() in {".docx", ".xlsx", ".pptx", ".zip"}:
                self._inject_zip_comment(str(dst), trap_id)
            else:
                self._append_watermark(str(dst), trap_id)
            stomp_timestamp(str(dst), config=self.stomp_config)
            logger.debug("Generated binary trap %s", dst.name)
        except Exception as exc:
            logger.error("Binary trap generation failed (%s): %s", dst, exc)
            raise

    def _inject_zip_comment(self, filepath: str, trap_id: str) -> None:
        try:
            with zipfile.ZipFile(filepath, mode="a") as zf:
                zf.comment = f"PHANTOM_ID:{trap_id}".encode("utf-8")
        except zipfile.BadZipFile:
            self._append_watermark(filepath, trap_id)

    def _append_watermark(self, filepath: str, trap_id: str) -> None:
        watermark = f"\n<!-- PHANTOM_TRAP_ID:{trap_id} -->".encode("utf-8")
        with open(filepath, "ab") as handle:
            handle.write(watermark)


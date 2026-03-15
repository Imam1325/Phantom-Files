"""
Плоскость управления (control-plane) для API-операций.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from phantom.core.config import get_config
from phantom.core.state import Decision
from phantom.factory.template_store import TemplateStore
from phantom.logging.audit import AuditLogger
from phantom.response.enforcement import NetworkEnforcer
from phantom.response.enforcement import ProcessEnforcer


logger = logging.getLogger("phantom.control_plane")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class BlockEntry:
    block_id: str
    kind: str
    targets: list[str]
    ttl_seconds: Optional[int]
    created_at: datetime
    expires_at: Optional[datetime]
    status: str
    requested_by: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "kind": self.kind,
            "targets": list(self.targets),
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "requested_by": self.requested_by,
        }


class ControlPlane:
    """
    Потокобезопасный бэкенд плоскости управления для API-обработчиков.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._lock = threading.RLock()
        self._audit = AuditLogger()
        self._network = NetworkEnforcer()
        self._process = ProcessEnforcer()

        cfg = get_config()
        paths = cfg.get("paths", {})
        templates_root = str(paths.get("user_templates_dir", "/etc/phantom/templates"))
        self._template_store = TemplateStore(templates_root)
        policy_path = Path(str(paths.get("policies", "config/policies.yaml")))
        if not policy_path.is_absolute():
            # Разрешаем относительный путь от корня проекта, а не от CWD
            project_root = Path(__file__).resolve().parent.parent.parent.parent
            policy_path = project_root / policy_path
        self._policies_path = policy_path

        self._incidents: dict[str, dict[str, Any]] = {}
        self._blocks: dict[str, BlockEntry] = {}
        # Кулдаун на изменение политик (минимум 30 секунд между изменениями)
        self._policy_cooldown_seconds = 30.0
        self._last_policy_change: float = 0.0

    async def initialize(self) -> None:
        await self._network.initialize()

    async def on_decision(self, decision: Decision) -> None:
        await asyncio.to_thread(self._on_decision_sync, decision)

    def _on_decision_sync(self, decision: Decision) -> None:
        context = decision.context
        incident_id = context.incident_id or f"INC-{decision.decision_id}"
        item = {
            "incident_id": incident_id,
            "decision_id": decision.decision_id,
            "event_id": context.event.event_id,
            "trap_id": context.event.trap_id,
            "trap_path": context.event.target_path,
            "process_pid": context.event.process_pid,
            "process_name": context.event.process_name,
            "severity": context.severity.name,
            "threat_category": context.threat_category.value,
            "threat_score": context.threat_score,
            "event_count": context.event_count,
            "actions": [action.value for action in decision.actions],
            "status": "open",
            "first_seen": context.event.timestamp.isoformat(),
            "updated_at": _utc_now().isoformat(),
            "mode": decision.mode.value,
            "rationale": decision.rationale,
        }
        with self._lock:
            prev = self._incidents.get(incident_id)
            if prev is not None:
                item["first_seen"] = prev.get("first_seen", item["first_seen"])
            self._incidents[incident_id] = item

    def list_incidents(self) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._incidents.values())
        values.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return values

    def get_incident(self, incident_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            item = self._incidents.get(incident_id)
            if item is None:
                return None
            return dict(item)

    def list_blocks(self) -> list[dict[str, Any]]:
        with self._lock:
            now = _utc_now()
            to_delete: list[str] = []
            output: list[dict[str, Any]] = []
            for block_id, block in self._blocks.items():
                if block.expires_at and block.expires_at <= now:
                    to_delete.append(block_id)
                    continue
                output.append(block.to_dict())
            for block_id in to_delete:
                del self._blocks[block_id]
        output.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return output

    def create_block(self, payload: dict[str, Any], role: str) -> dict[str, Any]:
        kind = str(payload.get("kind", "ip")).strip().lower()
        raw_targets = payload.get("targets", [])
        if isinstance(raw_targets, str):
            targets = [raw_targets.strip()] if raw_targets.strip() else []
        elif isinstance(raw_targets, list):
            targets = [str(item).strip() for item in raw_targets if str(item).strip()]
        else:
            targets = []
        if kind not in {"ip", "process"}:
            raise ValueError("kind must be 'ip' or 'process'")
        if not targets:
            raise ValueError("targets must contain at least one value")

        ttl_seconds: Optional[int] = payload.get("ttl_seconds")
        if ttl_seconds is not None:
            ttl_seconds = int(ttl_seconds)
            if ttl_seconds < 0:
                raise ValueError("ttl_seconds must be >= 0")

        if kind == "ip":
            ok = self._submit_network_block(targets, ttl_seconds)
        else:
            ok = self._submit_process_block(targets, ttl_seconds)
        status = "active" if ok else "failed"

        now = _utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds and ttl_seconds > 0 else None
        entry = BlockEntry(
            block_id=f"BLK-{uuid.uuid4().hex[:10]}",
            kind=kind,
            targets=targets,
            ttl_seconds=ttl_seconds,
            created_at=now,
            expires_at=expires_at,
            status=status,
            requested_by=role,
        )
        with self._lock:
            self._blocks[entry.block_id] = entry
        self._audit.log(extra={"api_action": "create_block", "role": role, "block": entry.to_dict()})
        return entry.to_dict()

    def list_templates(self) -> list[dict[str, Any]]:
        return self._template_store.to_dict_list()

    def get_template_info(self, name: str) -> dict[str, Any]:
        info = self._template_store.get_template_info(name)
        return {
            "name": info.name,
            "versions": info.versions,
            "active_version": info.active_version,
            "active_path": info.active_path,
            "total_size_bytes": info.total_size_bytes,
            "created_at": info.created_at,
            "extension": info.extension,
        }

    def mutate_templates(self, payload: dict[str, Any], role: str) -> dict[str, Any]:
        action = str(payload.get("action", "add")).strip().lower()
        if action == "add":
            if role not in {"admin", "editor"}:
                raise PermissionError("role does not allow template add")
            source = str(payload.get("source", "")).strip()
            name = str(payload.get("name", "")).strip()
            version = str(payload.get("version", "")).strip()
            if not source or not name or not version:
                raise ValueError("source, name, version are required")
            path = self._template_store.add_template(source=source, name=name, version=version)
            result = {"action": "add", "name": name, "version": version, "path": path}
            self._audit.log(extra={"api_action": "add_template", "role": role, "template": result})
            return result

        if action == "activate":
            if role != "admin":
                raise PermissionError("only admin can activate template")
            name = str(payload.get("name", "")).strip()
            version = str(payload.get("version", "")).strip()
            if not name or not version:
                raise ValueError("name and version are required")
            path = self._template_store.activate_template(name=name, version=version)
            result = {"action": "activate", "name": name, "version": version, "path": path}
            self._audit.log(extra={"api_action": "activate_template", "role": role, "template": result})
            return result

        if action == "remove":
            if role != "admin":
                raise PermissionError("only admin can remove templates")
            name = str(payload.get("name", "")).strip()
            version = payload.get("version")  # None = удалить все версии
            if not name:
                raise ValueError("name is required")
            if version is not None:
                version = str(version).strip()
            removed = self._template_store.remove_template(name, version)
            result = {"action": "remove", "name": name, "version": version, "removed_count": len(removed)}
            self._audit.log(extra={"api_action": "remove_template", "role": role, "template": result})
            return result

        if action == "show":
            name = str(payload.get("name", "")).strip()
            if not name:
                raise ValueError("name is required")
            return self.get_template_info(name)

        raise ValueError("Unsupported action. Use: add, activate, remove, show")

    def get_policies(self) -> dict[str, Any]:
        if not self._policies_path.exists():
            return {}
        text = self._policies_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return {}
        return data

    def update_policies(self, payload: dict[str, Any], role: str, replace: bool) -> dict[str, Any]:
        if role != "admin":
            raise PermissionError("only admin can modify policies")
        # Кулдаун: защита от слишком частых изменений политик
        import time
        now = time.monotonic()
        elapsed = now - self._last_policy_change
        if elapsed < self._policy_cooldown_seconds and self._last_policy_change > 0:
            remaining = int(self._policy_cooldown_seconds - elapsed)
            raise ValueError(
                f"Policy change cooldown: retry in {remaining}s"
            )
        current = self.get_policies()
        if replace:
            updated = dict(payload)
        else:
            updated = dict(current)
            updated.update(payload)
        self._policies_path.parent.mkdir(parents=True, exist_ok=True)
        self._policies_path.write_text(yaml.safe_dump(updated, sort_keys=True), encoding="utf-8")
        self._last_policy_change = now
        self._audit.log(extra={
            "api_action": "update_policies",
            "role": role,
            "replace": replace,
            "alert": "policy_changed",
        })
        logger.warning("Policies changed by user role=%s replace=%s", role, replace)
        return updated

    def _submit_network_block(self, ips: list[str], ttl_seconds: Optional[int]) -> bool:
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._network.block_ips(ips, ttl_seconds=ttl_seconds),
                self._loop,
            )
            return bool(future.result(timeout=10))
        except Exception:
            return False

    def _submit_process_block(self, targets: list[str], ttl_seconds: Optional[int]) -> bool:
        ok = True
        for target in targets:
            if not target.isdigit():
                ok = False
                continue
            pid = int(target)
            try:
                stop_future = asyncio.run_coroutine_threadsafe(self._process.sigstop(pid), self._loop)
                isolated_future = asyncio.run_coroutine_threadsafe(
                    self._network.isolate_process(pid, ttl_seconds=ttl_seconds),
                    self._loop,
                )
                stop_ok = bool(stop_future.result(timeout=5))
                isolated_ok = bool(isolated_future.result(timeout=10))
                ok = ok and stop_ok and isolated_ok
            except Exception:
                ok = False
        return ok

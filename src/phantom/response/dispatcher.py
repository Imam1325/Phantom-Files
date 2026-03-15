"""
Диспетчер действий по решениям.
"""

from __future__ import annotations

import logging
import time
from typing import Awaitable, Callable, Dict

from phantom.core.state import Decision, ResponseAction, ResponseResult, RunMode
from phantom.logging.audit import AuditLogger
from phantom.response.enforcement import NetworkEnforcer, ProcessEnforcer
from phantom.response.exporters import AlertExporter
from phantom.response.forensics import ForensicsCollector
from phantom.response.persistence import PersistenceScanner

logger = logging.getLogger("phantom.dispatcher")


class Dispatcher:
    def __init__(self) -> None:
        self._forensics = ForensicsCollector()
        self._audit = AuditLogger()
        self._process = ProcessEnforcer()
        self._network = NetworkEnforcer()
        self._exporter = AlertExporter()
        self._persistence = PersistenceScanner()
        self._handlers: Dict[ResponseAction, Callable[[Decision], Awaitable[ResponseResult]]] = {
            ResponseAction.LOG_ONLY: self._log_only,
            ResponseAction.ALERT: self._alert,
            ResponseAction.COLLECT_FORENSICS: self._collect_forensics,
            ResponseAction.ISOLATE_PROCESS: self._isolate_process,
            ResponseAction.BLOCK_NETWORK: self._block_network,
            ResponseAction.BLOCK_IP: self._block_ip,
            ResponseAction.KILL_PROCESS: self._kill_process,
            ResponseAction.QUARANTINE_FILE: self._quarantine_file,
            ResponseAction.SCAN_PERSISTENCE: self._scan_persistence,
            ResponseAction.KILL_USER_SESSIONS: self._kill_user_sessions,
        }

    async def initialize(self) -> None:
        await self._network.initialize()

    async def execute(self, decision: Decision) -> None:
        """
        Выполняет действия в заданном порядке.
        """
        started = time.monotonic()
        try:
            act_timeout = float(decision.action_params.get("act_timeout_seconds", 60.0))
        except (TypeError, ValueError):
            act_timeout = 60.0
        act_timeout = max(1.0, act_timeout)
        kill_executed = False
        for action in decision.actions:
            handler = self._handlers.get(action)
            if not handler:
                logger.warning("No handler for action %s", action.value)
                continue
            result = await handler(decision)
            self._audit.log(decision=decision, result=result)
            if action == ResponseAction.KILL_PROCESS:
                kill_executed = True

            if decision.mode == RunMode.ACTIVE and (time.monotonic() - started) >= act_timeout:
                logger.error("Act SLA exceeded (%.1fs), forcing SIGKILL", act_timeout)
                if not kill_executed:
                    force_result = await self._kill_process(decision)
                    self._audit.log(decision=decision, result=force_result)
                break

    def _action_blocked_by_mode(self, action: ResponseAction, mode: RunMode) -> bool:
        if mode == RunMode.DRY_RUN and action in {
            ResponseAction.ISOLATE_PROCESS,
            ResponseAction.BLOCK_NETWORK,
            ResponseAction.BLOCK_IP,
            ResponseAction.KILL_PROCESS,
            ResponseAction.QUARANTINE_FILE,
            ResponseAction.SCAN_PERSISTENCE,
            ResponseAction.KILL_USER_SESSIONS,
        }:
            return True
        if mode == RunMode.OBSERVATION and action in {
            ResponseAction.ISOLATE_PROCESS,
            ResponseAction.BLOCK_NETWORK,
            ResponseAction.BLOCK_IP,
            ResponseAction.KILL_PROCESS,
            ResponseAction.QUARANTINE_FILE,
            ResponseAction.SCAN_PERSISTENCE,
            ResponseAction.KILL_USER_SESSIONS,
        }:
            return True
        return False

    async def _log_only(self, decision: Decision) -> ResponseResult:
        message = f"log_only mode={decision.mode.value} priority={decision.priority}"
        logger.info(message)
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.LOG_ONLY,
            success=True,
            message=message,
        )

    async def _alert(self, decision: Decision) -> ResponseResult:
        message = f"ALERT mode={decision.mode.value} rationale={decision.rationale}"
        logger.warning(message)
        try:
            await self._exporter.export_alert(decision)
        except Exception as exc:
            logger.error("Alert export failed: %s", exc)
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.ALERT,
            success=True,
            message=message,
        )

    async def _collect_forensics(self, decision: Decision) -> ResponseResult:
        started = time.monotonic()
        try:
            artifacts = await self._forensics.collect(
                decision.context,
                params=decision.action_params.get("forensics", {}),
            )
            elapsed = int((time.monotonic() - started) * 1000)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.COLLECT_FORENSICS,
                success=True,
                message="forensics_collected",
                artifacts=tuple(artifacts),
                duration_ms=elapsed,
            )
        except Exception as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            logger.error("Forensics collection failed: %s", exc)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.COLLECT_FORENSICS,
                success=False,
                message="forensics_failed",
                error=str(exc),
                duration_ms=elapsed,
            )

    async def _isolate_process(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.ISOLATE_PROCESS, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.ISOLATE_PROCESS,
                success=True,
                message="blocked_by_mode",
            )

        pid = decision.context.event.process_pid
        if not pid:
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.ISOLATE_PROCESS,
                success=False,
                message="no_pid",
            )

        ok = await self._process.sigstop(pid)
        message = "sigstop_sent" if ok else "sigstop_failed"
        error = None
        if not ok:
            net_ok = await self._network.isolate_process(
                pid,
                ttl_seconds=decision.action_params.get("block_ttl_seconds"),
            )
            if net_ok:
                message = "sigstop_failed_network_isolated"
            else:
                error = "sigstop_failed_and_network_isolation_failed"
                logger.critical(
                    "CRITICAL containment failure pid=%s incident=%s decision=%s",
                    pid,
                    decision.context.incident_id,
                    decision.decision_id,
                )
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.ISOLATE_PROCESS,
            success=ok,
            message=message,
            error=error,
        )

    async def _kill_process(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.KILL_PROCESS, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_PROCESS,
                success=True,
                message="blocked_by_mode",
            )

        pid = decision.context.event.process_pid
        if not pid:
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_PROCESS,
                success=False,
                message="no_pid",
            )
        ok = await self._process.sigkill(pid)
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.KILL_PROCESS,
            success=ok,
            message="sigkill_sent" if ok else "sigkill_failed",
        )

    async def _block_network(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.BLOCK_NETWORK, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.BLOCK_NETWORK,
                success=True,
                message="blocked_by_mode",
            )

        ttl = decision.action_params.get("block_ttl_seconds")
        pid = decision.context.event.process_pid
        isolated = True
        if pid:
            isolated = await self._network.isolate_process(pid, ttl_seconds=ttl)
        ips = self._extract_ips(decision)
        ip_ok = await self._network.block_ips(ips, ttl_seconds=ttl)
        ok = isolated and ip_ok
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.BLOCK_NETWORK,
            success=ok,
            message="network_blocked" if ok else "network_block_partial_failed",
            error=None if ok else f"isolated={isolated},ip_blocked={ip_ok}",
        )

    async def _block_ip(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.BLOCK_IP, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.BLOCK_IP,
                success=True,
                message="blocked_by_mode",
            )

        ttl = decision.action_params.get("ip_block_ttl_seconds")
        ips = decision.action_params.get("ip_blacklist", [])
        if not isinstance(ips, list):
            ips = []
        ok = await self._network.block_ips([str(ip) for ip in ips], ttl_seconds=ttl)
        return ResponseResult(
            decision_id=decision.decision_id,
            action=ResponseAction.BLOCK_IP,
            success=ok,
            message="ip_blocked" if ok else "ip_block_failed",
        )

    async def _quarantine_file(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.QUARANTINE_FILE, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.QUARANTINE_FILE,
                success=True,
                message="blocked_by_mode",
            )

        target_path = decision.context.event.target_path
        if not target_path:
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.QUARANTINE_FILE,
                success=False,
                message="no_target_path",
            )

        import shutil
        from pathlib import Path

        src = Path(target_path)
        if not src.exists():
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.QUARANTINE_FILE,
                success=False,
                message="file_not_found",
            )

        try:
            quarantine_dir = Path("/var/lib/phantom/quarantine")
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dst = quarantine_dir / f"{src.name}.{decision.decision_id[:8]}"
            shutil.move(str(src), str(dst))
            dst.chmod(0o000)
            logger.info("Quarantined %s -> %s", src, dst)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.QUARANTINE_FILE,
                success=True,
                message=f"quarantined:{dst}",
                artifacts=(str(dst),),
            )
        except Exception as exc:
            logger.error("Quarantine failed for %s: %s", target_path, exc)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.QUARANTINE_FILE,
                success=False,
                message="quarantine_failed",
                error=str(exc),
            )

    async def _scan_persistence(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.SCAN_PERSISTENCE, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.SCAN_PERSISTENCE,
                success=True,
                message="blocked_by_mode",
            )

        pid = decision.context.event.process_pid
        if not pid:
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.SCAN_PERSISTENCE,
                success=False,
                message="no_pid",
            )

        started = time.monotonic()
        try:
            neutralize = decision.mode == RunMode.ACTIVE
            scan_result = await self._persistence.scan(pid, neutralize=neutralize)
            elapsed = int((time.monotonic() - started) * 1000)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.SCAN_PERSISTENCE,
                success=True,
                message=f"findings={len(scan_result.findings)},neutralized={sum(1 for f in scan_result.findings if f.neutralized)}",
                duration_ms=elapsed,
            )
        except Exception as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            logger.error("Persistence scan failed: %s", exc)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.SCAN_PERSISTENCE,
                success=False,
                message="scan_failed",
                error=str(exc),
                duration_ms=elapsed,
            )

    async def _kill_user_sessions(self, decision: Decision) -> ResponseResult:
        if self._action_blocked_by_mode(ResponseAction.KILL_USER_SESSIONS, decision.mode):
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_USER_SESSIONS,
                success=True,
                message="blocked_by_mode",
            )

        pid = decision.context.event.process_pid
        if not pid:
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_USER_SESSIONS,
                success=False,
                message="no_pid",
            )

        try:
            killed = await self._persistence.kill_user_sessions(pid)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_USER_SESSIONS,
                success=killed > 0,
                message=f"sessions_killed={killed}",
            )
        except Exception as exc:
            logger.error("Kill user sessions failed: %s", exc)
            return ResponseResult(
                decision_id=decision.decision_id,
                action=ResponseAction.KILL_USER_SESSIONS,
                success=False,
                message="kill_sessions_failed",
                error=str(exc),
            )

    def _extract_ips(self, decision: Decision) -> list[str]:
        ips: list[str] = []
        network = decision.context.network
        if not network:
            return ips
        for conn in network.connections:
            if conn.remote_addr and conn.remote_addr not in {"127.0.0.1", "::1", "0.0.0.0"}:
                ips.append(conn.remote_addr)
        return list(dict.fromkeys(ips))

"""
Оркестратор Phantom v1.0.0 — цикл OODA (Observe-Orient-Decide-Act).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

import yaml

from phantom.core.incidents import IncidentStore
from phantom.core.state import (
    Context,
    Decision,
    Event,
    EventType,
    ProcessInfo,
    ResponseAction,
    RunMode,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger("phantom.orchestrator")

DecisionCallback = Callable[[Decision], Awaitable[None]]


def _severity_from_name(name: str) -> Severity:
    name = name.upper().strip()
    if name in Severity.__members__:
        return Severity[name]
    return Severity.INFO


@dataclass
class OrchestratorConfig:
    orient_timeout: float = 5.0
    act_timeout: float = 60.0
    event_queue_size: int = 2000
    worker_count: int = 4
    dedup_window_seconds: float = 2.0
    auto_execute: bool = True
    min_severity: Severity = Severity.INFO
    mode: RunMode = RunMode.ACTIVE
    fail_close: bool = True
    degraded_timeout_block: bool = True
    block_ttl_seconds: Optional[int] = 3600
    ip_block_ttl_seconds: Optional[int] = 3600
    max_concurrent_actions: int = 32
    whitelist_process_names: Set[str] = field(default_factory=set)
    policies: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        sensors_cfg: Optional[Dict[str, Any]] = None,
        policies_cfg: Optional[Dict[str, Any]] = None,
    ) -> "OrchestratorConfig":
        sensors_cfg = sensors_cfg or {}
        policies_cfg = policies_cfg or {}
        mode_val = str(data.get("mode", data.get("run_mode", "active"))).lower()
        mode = RunMode.ACTIVE
        if mode_val == "observation":
            mode = RunMode.OBSERVATION
        elif mode_val in {"dry-run", "dry_run"}:
            mode = RunMode.DRY_RUN

        return cls(
            orient_timeout=float(data.get("orient_timeout", 5.0)),
            act_timeout=float(data.get("act_timeout", 60.0)),
            event_queue_size=int(data.get("event_queue_size", 2000)),
            worker_count=max(1, int(data.get("worker_count", 4))),
            dedup_window_seconds=float(data.get("event_dedup_window", data.get("dedup_window_seconds", 2.0))),
            auto_execute=bool(data.get("auto_execute", True)),
            min_severity=_severity_from_name(str(data.get("min_severity", "INFO"))),
            mode=mode,
            fail_close=bool(data.get("fail_close", True)),
            degraded_timeout_block=bool(data.get("degraded_timeout_block", True)),
            block_ttl_seconds=data.get("block_ttl_seconds", 3600),
            ip_block_ttl_seconds=data.get("ip_block_ttl_seconds", 3600),
            max_concurrent_actions=max(1, int(data.get("max_concurrent_actions", 32))),
            whitelist_process_names=set(sensors_cfg.get("whitelist_process_names", [])),
            policies=dict(policies_cfg),
        )


class TelemetryCollector:
    def __init__(self) -> None:
        self._process_collector: Optional[Any] = None
        self._fs_collector: Optional[Any] = None
        self._network_collector: Optional[Any] = None
        self._initialized = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        self._process_collector = self._try_import("phantom.telemetry.processes", "ProcessCollector")
        self._fs_collector = self._try_import("phantom.telemetry.file_system", "FileSystemCollector")
        self._network_collector = self._try_import("phantom.telemetry.network", "NetworkCollector")
        self._initialized = True

    def _try_import(self, module_path: str, class_name: str) -> Optional[Any]:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            return getattr(mod, class_name)()
        except Exception as exc:
            logger.debug("Failed to load %s: %s", class_name, exc)
            return None

    async def collect(self, event: Event) -> tuple[Optional[ProcessInfo], Any, Any]:
        """Параллельный сбор телеметрии через asyncio.gather."""
        if not self._initialized:
            await self.initialize()

        results = await asyncio.gather(
            self._collect_proc(event.process_pid) if event.process_pid else self._noop(),
            self._collect_fs(event.target_path),
            self._collect_net(event.process_pid) if event.process_pid else self._noop(),
            return_exceptions=True,
        )
        # Исключения из gather заменяем на None
        proc = results[0] if not isinstance(results[0], BaseException) else None
        file_info = results[1] if not isinstance(results[1], BaseException) else None
        network = results[2] if not isinstance(results[2], BaseException) else None
        return proc, file_info, network

    @staticmethod
    async def _noop() -> None:
        """Заглушка для отсутствующих коллекторов."""
        return None

    async def _collect_proc(self, pid: int) -> Optional[ProcessInfo]:
        if not self._process_collector:
            return None
        try:
            return await self._process_collector.collect(pid)
        except Exception:
            return None

    async def _collect_fs(self, path: str):
        if not self._fs_collector:
            return None
        try:
            return await self._fs_collector.collect(path)
        except Exception:
            return None

    async def _collect_net(self, pid: int):
        if not self._network_collector:
            return None
        try:
            return await self._network_collector.collect(pid)
        except Exception:
            return None


class ThreatAnalyzer:
    def __init__(self, config: OrchestratorConfig) -> None:
        self._config = config
        self._whitelist_lower = {p.lower() for p in config.whitelist_process_names}

    def analyze(self, event: Event, process: Optional[ProcessInfo]) -> tuple[ThreatCategory, float, frozenset[str]]:
        indicators: set[str] = set()
        score = 0.75
        category = ThreatCategory.RECONNAISSANCE

        if event.trap_id:
            indicators.add(f"trap:{event.trap_id}")
            score = 0.95

        if process and process.name:
            name = process.name.lower()
            if name in self._whitelist_lower:
                return ThreatCategory.UNKNOWN, 0.0, frozenset({"whitelist_process"})
            if name in {"bash", "sh", "zsh", "python", "perl", "ruby", "curl", "wget", "ncat", "nc"}:
                indicators.add(f"suspicious_process:{name}")
                score = min(1.0, score + 0.04)

        if event.event_type in {
            EventType.FILE_DELETE,
            EventType.FILE_RENAME,
            EventType.FILE_WRITE,
            EventType.FILE_MODIFY,
        }:
            category = ThreatCategory.PERSISTENCE
            score = min(1.0, score + 0.03)

        return category, score, frozenset(indicators)


class DecisionEngine:
    def __init__(self, config: OrchestratorConfig) -> None:
        self._config = config

    def decide(self, context: Context, sensor_degraded: bool = False) -> Decision:
        actions: list[ResponseAction] = [ResponseAction.ALERT]
        params: dict[str, Any] = {
            "block_ttl_seconds": self._config.block_ttl_seconds,
            "ip_block_ttl_seconds": self._config.ip_block_ttl_seconds,
            "act_timeout_seconds": self._config.act_timeout,
        }
        rationale = [f"mode={self._config.mode.value}", f"severity={context.severity.name}"]
        policy = self._resolve_policy_for_mode(self._config.mode)
        if policy:
            parsed_actions = self._parse_actions(policy.get("actions"))
            if parsed_actions:
                actions = list(parsed_actions)
            if "block_ttl_seconds" in policy:
                params["block_ttl_seconds"] = policy.get("block_ttl_seconds")
            if "ip_block_ttl_seconds" in policy:
                params["ip_block_ttl_seconds"] = policy.get("ip_block_ttl_seconds")
            rationale.append(f"policy={policy.get('description', 'loaded')}")

        if self._config.mode == RunMode.DRY_RUN:
            if ResponseAction.COLLECT_FORENSICS not in actions:
                actions.append(ResponseAction.COLLECT_FORENSICS)
            rationale.append("dry_run_no_block")
            return Decision.from_context(
                context=context,
                actions=tuple(actions),
                rationale=";".join(rationale),
                auto_execute=self._config.auto_execute,
                action_params=params,
                mode=self._config.mode,
            )

        if self._config.mode == RunMode.OBSERVATION:
            if ResponseAction.COLLECT_FORENSICS not in actions:
                actions.append(ResponseAction.COLLECT_FORENSICS)
            rationale.append("observation_mode")
            return Decision.from_context(
                context=context,
                actions=tuple(actions),
                rationale=";".join(rationale),
                auto_execute=self._config.auto_execute,
                action_params=params,
                mode=self._config.mode,
            )

        # Active mode pipeline:
        # 1) stop process
        # 2) collect forensics
        # 3) block network
        # 4) kill process
        # 5) scan for persistence mechanisms
        # 6) kill all attacker sessions
        if not policy:
            actions.extend(
                [
                    ResponseAction.ISOLATE_PROCESS,
                    ResponseAction.COLLECT_FORENSICS,
                    ResponseAction.BLOCK_NETWORK,
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.SCAN_PERSISTENCE,
                    ResponseAction.KILL_USER_SESSIONS,
                ]
            )
        remote_ips: list[str] = []
        if context.network:
            for conn in context.network.connections:
                if conn.remote_addr and conn.remote_addr not in {"127.0.0.1", "::1", "0.0.0.0"}:
                    remote_ips.append(conn.remote_addr)
        if remote_ips:
            params["ip_blacklist"] = list(dict.fromkeys(remote_ips))
            if ResponseAction.BLOCK_IP not in actions:
                if ResponseAction.KILL_PROCESS in actions:
                    idx = actions.index(ResponseAction.KILL_PROCESS)
                    actions.insert(idx, ResponseAction.BLOCK_IP)
                else:
                    actions.append(ResponseAction.BLOCK_IP)
        if sensor_degraded and self._config.degraded_timeout_block:
            rationale.append("degraded_mode_fail_close")
        return Decision.from_context(
            context=context,
            actions=tuple(actions),
            rationale=";".join(rationale),
            auto_execute=self._config.auto_execute,
            action_params=params,
            mode=self._config.mode,
        )

    def _resolve_policy_for_mode(self, mode: RunMode) -> Optional[dict[str, Any]]:
        policies = self._config.policies
        if not isinstance(policies, dict):
            return None
        if mode == RunMode.ACTIVE:
            value = policies.get("default")
        elif mode == RunMode.OBSERVATION:
            value = policies.get("observation")
        else:
            value = policies.get("dry_run")
        if isinstance(value, dict):
            return value
        return None

    def _parse_actions(self, raw: Any) -> tuple[ResponseAction, ...]:
        if not isinstance(raw, list):
            return tuple()
        parsed: list[ResponseAction] = []
        for item in raw:
            name = str(item).strip().upper()
            if name in ResponseAction.__members__:
                parsed.append(ResponseAction[name])
                continue
            # also accept enum value form: "collect_forensics"
            for action in ResponseAction:
                if action.value == str(item).strip():
                    parsed.append(action)
                    break
        # de-duplicate preserving order
        uniq: list[ResponseAction] = []
        for action in parsed:
            if action not in uniq:
                uniq.append(action)
        return tuple(uniq)


class Orchestrator:
    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        *,
        sensor_degraded: bool = False,
    ) -> None:
        self._config = config or OrchestratorConfig()
        self._sensor_degraded = sensor_degraded
        self._telemetry = TelemetryCollector()
        self._analyzer = ThreatAnalyzer(self._config)
        self._engine = DecisionEngine(self._config)
        self._incidents = IncidentStore(self._config.dedup_window_seconds)
        self._whitelist_lower = {p.lower() for p in self._config.whitelist_process_names}
        self._reload_lock = asyncio.Lock()

        self._dispatcher: Optional[Any] = None
        self._event_queue: asyncio.Queue[Optional[Event]] = asyncio.Queue(maxsize=self._config.event_queue_size)
        self._workers: List[asyncio.Task] = []
        self._pending_actions: Set[asyncio.Task] = set()
        self._decision_callbacks: List[DecisionCallback] = []
        self._action_semaphore = asyncio.Semaphore(self._config.max_concurrent_actions)
        self._running = False

        self._stats = {
            "events_received": 0,
            "events_filtered_severity": 0,
            "events_dropped_queue_full": 0,
            "events_processed": 0,
            "actions_dispatched": 0,
            "actions_failed": 0,
            "errors": 0,
            "mode": self._config.mode.value,
        }
        # Защита от гонки при конкурентном обновлении счётчиков
        self._stats_lock = asyncio.Lock()

    async def start(self) -> None:
        if self._running:
            return

        try:
            from phantom.response.dispatcher import Dispatcher

            self._dispatcher = Dispatcher()
            await self._dispatcher.initialize()
        except Exception as exc:
            logger.error("Dispatcher init failed: %s", exc)
            self._dispatcher = None

        await self._telemetry.initialize()
        self._running = True
        for idx in range(self._config.worker_count):
            self._workers.append(asyncio.create_task(self._worker_loop(idx)))
        logger.info("Orchestrator started (%s workers)", self._config.worker_count)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        for _ in self._workers:
            await self._event_queue.put(None)
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
        if self._pending_actions:
            done, pending = await asyncio.wait(self._pending_actions, timeout=5.0)
            for task in pending:
                task.cancel()

    def subscribe_decisions(self, callback: DecisionCallback) -> None:
        self._decision_callbacks.append(callback)

    def set_sensor_degraded(self, degraded: bool) -> None:
        self._sensor_degraded = bool(degraded)

    async def reload_settings(self, raw_config: Dict[str, Any]) -> None:
        async with self._reload_lock:
            sensors_cfg = dict(raw_config.get("sensors", {}))
            policies_cfg = _load_policies_from_config(raw_config)
            updated = OrchestratorConfig.from_dict(
                dict(raw_config.get("orchestrator", {})),
                sensors_cfg=sensors_cfg,
                policies_cfg=policies_cfg,
            )
            self._config = updated
            self._analyzer = ThreatAnalyzer(updated)
            self._engine = DecisionEngine(updated)
            # Сохраняем IncidentStore между перезагрузками,
            # чтобы не потерять контекст текущих инцидентов.
            # Обновляем только окно дедупликации.
            self._incidents.dedup_window = updated.dedup_window_seconds
            self._whitelist_lower = {p.lower() for p in updated.whitelist_process_names}
            self._stats["mode"] = updated.mode.value

    async def handle_event(self, event: Event) -> None:
        proc_name = (event.process_name or "").strip().lower()
        async with self._reload_lock:
            whitelist = self._whitelist_lower
            config = self._config
        if bool(event.raw_data.get("benign")) or (proc_name and proc_name in whitelist):
            logger.info(
                "Benign trap touch ignored pid=%s name=%s path=%s sensor=%s",
                event.process_pid,
                event.process_name,
                event.target_path,
                event.source_sensor,
            )
            return
        await self._inc_stat("events_received")
        if event.severity.value < config.min_severity.value:
            await self._inc_stat("events_filtered_severity")
            return
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            await self._inc_stat("events_dropped_queue_full")
            logger.error("Event queue full")

    async def pre_authorize(self, event: Event) -> bool:
        """
        Fast-path authorization for fanotify PERM.

        Returns True to allow kernel access and False to deny.
        """
        proc_name = (event.process_name or "").lower()
        async with self._reload_lock:
            whitelist = self._whitelist_lower
            config = self._config
        if proc_name and proc_name in whitelist:
            return True
        if config.mode in {RunMode.OBSERVATION, RunMode.DRY_RUN}:
            return True
        if not config.fail_close:
            return True
        return False

    async def _worker_loop(self, worker_id: int) -> None:
        while True:
            event = await self._event_queue.get()
            if event is None:
                self._event_queue.task_done()
                break
            try:
                await self._process_event(event)
                await self._inc_stat("events_processed")
            except Exception:
                logger.exception("Worker %s failed processing event", worker_id)
                await self._inc_stat("errors")
            finally:
                self._event_queue.task_done()

    async def _process_event(self, event: Event) -> None:
        incident = await self._incidents.upsert(event)
        try:
            context = await asyncio.wait_for(self._orient(event, incident.event_count, incident.incident_id), timeout=self._config.orient_timeout)
        except asyncio.TimeoutError:
            if self._sensor_degraded and self._config.fail_close:
                logger.critical("Orient timeout in degraded mode: enforcing fail-close")
            context = Context(
                event=event,
                threat_category=ThreatCategory.UNKNOWN,
                threat_score=1.0 if (self._sensor_degraded and self._config.fail_close) else 0.5,
                anomaly_indicators=frozenset({"timeout:orient"}),
                incident_id=incident.incident_id,
                event_count=incident.event_count,
            )

        if "whitelist_process" in context.anomaly_indicators:
            logger.info(
                "Benign trap touch ignored for whitelisted process pid=%s name=%s",
                context.event.process_pid,
                context.event.process_name,
            )
            return
        decision = self._engine.decide(context, sensor_degraded=self._sensor_degraded)
        for callback in self._decision_callbacks:
            task = asyncio.create_task(self._safe_callback(callback, decision))
            self._pending_actions.add(task)
            task.add_done_callback(self._pending_actions.discard)
        if decision.auto_execute and decision.actions:
            self._dispatch_act(decision)

    async def _orient(self, event: Event, event_count: int, incident_id: str) -> Context:
        process, file_info, network = await self._telemetry.collect(event)
        category, score, indicators = self._analyzer.analyze(event, process)
        if "whitelist_process" in indicators:
            # fully ignored in processing path
            return Context(
                event=event,
                process=process,
                file=file_info,
                network=network,
                threat_category=ThreatCategory.UNKNOWN,
                threat_score=0.0,
                anomaly_indicators=indicators,
                incident_id=incident_id,
                event_count=event_count,
            )
        return Context(
            event=event,
            process=process,
            file=file_info,
            network=network,
            threat_category=category,
            threat_score=score,
            anomaly_indicators=indicators,
            incident_id=incident_id,
            event_count=event_count,
        )

    async def _safe_callback(self, callback: DecisionCallback, decision: Decision) -> None:
        try:
            await callback(decision)
        except Exception as exc:
            logger.error("Decision callback failed: %s", exc)

    def _dispatch_act(self, decision: Decision) -> None:
        task = asyncio.create_task(self._act_wrapper(decision))
        self._pending_actions.add(task)
        task.add_done_callback(self._pending_actions.discard)
        # Безопасный инкремент без await (fire-and-forget из синхронного контекста)
        asyncio.create_task(self._inc_stat("actions_dispatched"))

    async def _act_wrapper(self, decision: Decision) -> None:
        async with self._action_semaphore:
            if not self._dispatcher:
                return
            try:
                await self._dispatcher.execute(decision)
            except Exception as exc:
                logger.error("Act pipeline failed: %s", exc)
                await self._inc_stat("actions_failed")

    async def _inc_stat(self, key: str, delta: int = 1) -> None:
        """Потокобезопасное обновление счётчика."""
        async with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + delta

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)


def create_orchestrator(config_path: Optional[str] = None, sensor_degraded: bool = False) -> Orchestrator:
    from phantom.core.config import get_config

    raw = get_config(config_path)
    policies_cfg = _load_policies_from_config(dict(raw))
    orch_cfg = OrchestratorConfig.from_dict(
        dict(raw.get("orchestrator", {})),
        sensors_cfg=dict(raw.get("sensors", {})),
        policies_cfg=policies_cfg,
    )
    return Orchestrator(orch_cfg, sensor_degraded=sensor_degraded)


def _load_policies_from_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    from phantom.core.config import PROJECT_ROOT

    paths = raw.get("paths", {})
    policy_path = str(paths.get("policies", "config/policies.yaml")).strip()
    if not policy_path:
        return {}
    p = Path(policy_path)
    if not p.is_absolute():
        # Разрешаем относительный путь от корня проекта, а не от CWD
        p = PROJECT_ROOT / p
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(data, dict):
        return data
    return {}

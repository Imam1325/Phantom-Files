"""
Контракты данных ядра Phantom v1.0.0.
"""

from __future__ import annotations

import base64
import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Mapping, Optional, Union


JSONPrimitive = Union[str, int, float, bool, None]
JSONValue = Union[JSONPrimitive, Dict[str, Any], list]
JSONDict = Dict[str, JSONValue]

SCHEMA_VERSION = "1.0.0"


def _to_jsonable(value: Any) -> JSONValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"__bytes_b64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if hasattr(value, "to_dict"):
            return value.to_dict()
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, MappingProxyType):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, frozenset)):
        return [_to_jsonable(v) for v in value]
    return {"__repr__": repr(value)[:300], "__type__": type(value).__name__}


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return MappingProxyType({str(k): _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, dict):
        return MappingProxyType({str(k): _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(v) for v in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(v) for v in value)
    if isinstance(value, frozenset):
        return frozenset(_deep_freeze(v) for v in value)
    return value


def _freeze_dict(data: Optional[Dict[str, Any]]) -> MappingProxyType:
    if data is None:
        return MappingProxyType({})
    if not isinstance(data, dict):
        raise TypeError(f"Expected dict, got {type(data).__name__}")
    for key in data.keys():
        if not isinstance(key, str):
            raise TypeError("Dictionary keys must be strings")
    return _deep_freeze({k: _to_jsonable(v) for k, v in data.items()})


class RunMode(str, Enum):
    ACTIVE = "active"
    OBSERVATION = "observation"
    DRY_RUN = "dry_run"


class EventType(str, Enum):
    FILE_OPEN = "file_open"
    FILE_ACCESS = "file_access"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    FILE_CHMOD = "file_chmod"
    FILE_CHOWN = "file_chown"
    FILE_ATTRIB = "file_attrib"
    SENSOR_ERROR = "sensor_error"
    HEARTBEAT = "heartbeat"


class Severity(int, Enum):
    DEBUG = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ThreatCategory(str, Enum):
    UNKNOWN = "unknown"
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ResponseAction(str, Enum):
    LOG_ONLY = "log_only"
    ALERT = "alert"
    COLLECT_FORENSICS = "collect_forensics"
    ISOLATE_PROCESS = "isolate_process"
    BLOCK_NETWORK = "block_network"
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    SCAN_PERSISTENCE = "scan_persistence"
    KILL_USER_SESSIONS = "kill_user_sessions"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    argv: tuple[str, ...] = field(default_factory=tuple)
    environ: Mapping[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    root: Optional[str] = None
    user: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    start_time: Optional[datetime] = None
    ancestors: tuple[str, ...] = field(default_factory=tuple)
    pid_ns: Optional[int] = None
    mnt_ns: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "environ", _freeze_dict(dict(self.environ)))


@dataclass(frozen=True)
class FileInfo:
    path: str
    inode: Optional[int] = None
    size: Optional[int] = None
    owner_uid: Optional[int] = None
    owner_gid: Optional[int] = None
    mode: Optional[int] = None
    mtime: Optional[datetime] = None
    atime: Optional[datetime] = None
    ctime: Optional[datetime] = None
    trap_id: Optional[str] = None
    trap_type: Optional[str] = None


@dataclass(frozen=True)
class NetworkConnection:
    local_addr: str
    local_port: int
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: str = "tcp"
    state: str = "UNKNOWN"
    fd: Optional[int] = None
    inode: Optional[int] = None


@dataclass(frozen=True)
class NetworkInfo:
    local_addr: Optional[str] = None
    local_port: Optional[int] = None
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None
    connections: tuple[NetworkConnection, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Event:
    event_type: EventType
    target_path: str
    source_sensor: str = "unknown"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    process_uid: Optional[int] = None
    severity: Severity = Severity.INFO
    trap_id: Optional[str] = None
    raw_data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_data", _freeze_dict(dict(self.raw_data)))

    def to_dict(self) -> JSONDict:
        return {
            "schema_version": SCHEMA_VERSION,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_sensor": self.source_sensor,
            "target_path": self.target_path,
            "trap_id": self.trap_id,
            "process_pid": self.process_pid,
            "process_name": self.process_name,
            "process_uid": self.process_uid,
            "severity": self.severity.value,
            "raw_data": _to_jsonable(self.raw_data),
        }


@dataclass(frozen=True)
class Context:
    event: Event
    process: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    network: Optional[NetworkInfo] = None
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    threat_score: float = 0.0
    related_events: tuple[str, ...] = field(default_factory=tuple)
    anomaly_indicators: FrozenSet[str] = field(default_factory=frozenset)
    enrichment_data: Mapping[str, Any] = field(default_factory=dict)
    incident_id: Optional[str] = None
    event_count: int = 1

    def __post_init__(self) -> None:
        if not 0.0 <= self.threat_score <= 1.0:
            raise ValueError(f"threat_score must be between 0.0 and 1.0, got {self.threat_score}")
        if self.event_count < 1:
            raise ValueError("event_count must be >= 1")
        object.__setattr__(self, "enrichment_data", _freeze_dict(dict(self.enrichment_data)))

    @property
    def severity(self) -> Severity:
        if self.threat_score >= 0.9:
            computed = Severity.CRITICAL
        elif self.threat_score >= 0.7:
            computed = Severity.HIGH
        elif self.threat_score >= 0.5:
            computed = Severity.MEDIUM
        elif self.threat_score >= 0.3:
            computed = Severity.LOW
        else:
            computed = Severity.INFO
        return max(self.event.severity, computed, key=lambda s: s.value)

    def to_dict(self) -> JSONDict:
        return {
            "schema_version": SCHEMA_VERSION,
            "event": self.event.to_dict(),
            "process": _to_jsonable(self.process) if self.process else None,
            "file": _to_jsonable(self.file) if self.file else None,
            "network": _to_jsonable(self.network) if self.network else None,
            "threat_category": self.threat_category.value,
            "threat_score": self.threat_score,
            "severity": self.severity.value,
            "related_events": list(self.related_events),
            "anomaly_indicators": list(self.anomaly_indicators),
            "enrichment_data": _to_jsonable(self.enrichment_data),
            "incident_id": self.incident_id,
            "event_count": self.event_count,
        }


@dataclass(frozen=True)
class Decision:
    context: Context
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actions: tuple[ResponseAction, ...] = field(default_factory=tuple)
    priority: int = 0
    rationale: str = ""
    action_params: Mapping[str, Any] = field(default_factory=dict)
    auto_execute: bool = True
    mode: RunMode = RunMode.ACTIVE

    def __post_init__(self) -> None:
        if not 0 <= self.priority <= 5:
            raise ValueError(f"priority must be 0-5, got {self.priority}")
        object.__setattr__(self, "action_params", _freeze_dict(dict(self.action_params)))

    @classmethod
    def from_context(
        cls,
        context: Context,
        actions: tuple[ResponseAction, ...],
        rationale: str = "",
        auto_execute: bool = True,
        action_params: Optional[Dict[str, Any]] = None,
        mode: RunMode = RunMode.ACTIVE,
    ) -> "Decision":
        return cls(
            context=context,
            actions=actions,
            priority=context.severity.value,
            rationale=rationale,
            action_params=action_params or {},
            auto_execute=auto_execute,
            mode=mode,
        )

    def to_dict(self) -> JSONDict:
        return {
            "schema_version": SCHEMA_VERSION,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.context.event.event_id,
            "incident_id": self.context.incident_id,
            "actions": [a.value for a in self.actions],
            "priority": self.priority,
            "rationale": self.rationale,
            "action_params": _to_jsonable(self.action_params),
            "auto_execute": self.auto_execute,
            "mode": self.mode.value,
        }


@dataclass(frozen=True)
class ResponseResult:
    decision_id: str
    action: ResponseAction
    success: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = ""
    error: Optional[str] = None
    artifacts: tuple[str, ...] = field(default_factory=tuple)
    duration_ms: Optional[int] = None

    def to_dict(self) -> JSONDict:
        return {
            "schema_version": SCHEMA_VERSION,
            "decision_id": self.decision_id,
            "action": self.action.value,
            "success": self.success,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "error": self.error,
            "artifacts": list(self.artifacts),
            "duration_ms": self.duration_ms,
        }


def create_file_access_event(
    path: str,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    process_uid: Optional[int] = None,
    trap_id: Optional[str] = None,
    sensor: str = "inotify",
    raw_data: Optional[Dict[str, Any]] = None,
    event_type: EventType = EventType.FILE_ACCESS,
) -> Event:
    return Event(
        event_type=event_type,
        target_path=path,
        source_sensor=sensor,
        process_pid=pid,
        process_name=process_name,
        process_uid=process_uid,
        trap_id=trap_id,
        severity=Severity.HIGH,
        raw_data=raw_data or {},
    )


def generate_incident_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"INC-{ts}-{uuid.uuid4().hex[:8]}"


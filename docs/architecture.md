# Architecture Overview (v2)

## Runtime Flow
1. `TrapFactory` deploys traps and writes `trap_registry.json`.
2. `SensorManager` selects sensor:
   - primary: fanotify PERM (pre-access allow/deny),
   - parallel telemetry: eBPF filesystem sensor (`sys_enter_*` tracepoints),
   - fallback: inotify degraded mode.
3. Sensor events are passed to `Orchestrator`.
4. `Orchestrator` aggregates incidents, enriches telemetry, builds decision.
5. `Dispatcher` executes response chain according to mode.
6. Forensics collector creates evidence bundle, integrity metadata, PCAP pre/post capture, optional sandbox run, and optional S3/MinIO replication.

## Main Modules
- `core/state.py`: immutable data contracts (event/context/decision/result).
- `core/incidents.py`: dedup and incident event counters.
- `core/orchestrator.py`: policy and action pipeline.
- `core/traps.py`: trap registry and path normalization.
- `sensors/*`: event capture and fallback handling.
- `sensors/ebpf/*.c`: kernel eBPF programs for FS telemetry and packet pre-capture.
- `response/*`: enforcement and forensic collection.
- `telemetry/precapture.py`: bounded 64MB pre-capture packet ring and export to PCAP.
- `response/exporters.py`: webhook/syslog/telegram alert delivery.
- `response/storage.py`: AES-256-GCM evidence encryption and S3/MinIO upload.
- `factory/*`: secure template rendering and trap deployment.
- `api/asgi_app.py`: `/api/v1/*` control and health endpoints (ASGI).

## Fail-Close Behavior
- Fanotify PERM path is defined as primary enforcement interface.
- Fanotify verdict timeout is deny (`fail-close`) in active mode.
- If only inotify is available, daemon marks health as degraded and switches to
  aggressive post-event containment.

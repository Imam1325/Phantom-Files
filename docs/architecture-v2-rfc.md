# Phantom Files Daemon v2.0 RFC

## 1. Goals
- Production Active Defense for Linux 5.10+.
- Deception-only detection (registered trap files only).
- Fail-Close on policy decision timeout when pre-access enforcement is available.
- Default action chain in Active mode: `SIGSTOP -> forensics (<=60s) -> network isolation -> SIGKILL`.

## 2. Operating Modes
- `active`: full enforcement (process/network/ip blocking).
- `observation`: no destructive actions; optional `SIGCONT` allowed by policy.
- `dry_run`: no blocking actions, full telemetry/forensics/logging.

## 3. Sensor Architecture
- Primary: eBPF sensor (event telemetry + context collection).
- Enforcement layer: fanotify PERM (pre-access allow/deny decision for trap files).
- Fallback: inotify degraded mode with immediate containment after event.

## 4. Fail-Close Semantics
- If fanotify permission decision times out: kernel deny.
- If only inotify available and decision pipeline fails/timeouts:
  - create CRITICAL alert,
  - send immediate `SIGSTOP`,
  - attempt network isolation,
  - continue forensic collection.
- Service shutdown is allowed only if secure startup is impossible.

## 5. Response Policy
- Trap access is incident by definition (except whitelist).
- Dedup key: `trap_path + pid` over 1-2 seconds; event counter increments in same incident.
- Whitelisted processes are logged as benign and ignored.

## 6. Forensics Requirements (v2 baseline)
- Process: pid/ppid/uid/gid/ns ids, cmdline, argv, environ.
- File context: cwd/root/exe/fds/maps.
- Network: sockets and connection snapshots.
- Memory dump: native attempt (`/proc/<pid>/mem` or `process_vm_readv` abstraction), fallback to `gcore`.
- Collection SLA: hard timeout 60s.

## 7. Evidence Integrity
- Every evidence package includes:
  - SHA-256 hash manifest,
  - hash-chain link to previous incident package,
  - Ed25519 signature (if key configured).

## 8. Template Security Model
- System templates: `resources/templates` and `/etc/phantom/templates`.
- User templates via `phantomctl` and filesystem GitOps.
- Jinja rendering: `SandboxedEnvironment + StrictUndefined`.
- File limits and format validation before activation.

## 9. API
- Prefix: `/api/v1`.
- Minimal endpoints: incidents, blocks, templates, policies, health.
- Security modes: `mtls | api_key | jwt | both`.

## 10. Module Mapping
- `core/config.py`: strict config parsing + policy modes.
- `core/orchestrator.py`: incident lifecycle and decision pipeline.
- `sensors/*`: primary/fallback event source adapters.
- `response/*`: enforcement and forensic pipeline.
- `factory/*` + `templates/*`: secure trap rendering and registry updates.
- `logging/*`: audit trail, incident chain, integrity metadata.

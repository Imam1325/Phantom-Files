# Threat Model (v2)

## Assets
- Trap files and trap registry.
- Evidence bundles and integrity chain.
- Policy configuration and template store.
- API control plane.

## Adversary Assumptions
- Attacker can execute code on host.
- Attacker may escalate to root.
- Attacker can attempt anti-forensics (log cleanup, tampering, file deletion).

## Security Objectives
- Detect access to registered traps with near-zero false positives.
- Contain suspicious process quickly (`SIGSTOP`, network isolation).
- Preserve forensic context before process termination.
- Protect evidence integrity using hashes and signatures.

## Trust Boundaries
- Kernel events -> user-space daemon.
- Local host -> API endpoint.
- Local buffer -> external evidence storage (S3/MinIO pipeline).
- Local alerts -> external webhooks / syslog / Telegram.

## Key Risks and Mitigations
- Sensor unavailability:
  - Primary fanotify/eBPF unavailable -> fallback inotify with degraded alert.
- Decision timeout:
  - In degraded mode triggers immediate containment path.
- Path traversal in templates/outputs:
  - strict relative path checks and root confinement.
- Evidence tampering:
  - hash manifest + hash chain + optional Ed25519 signature.
- Alert data exfiltration:
  - process environment collection disabled by default; export sanitization drops `process.environ`.

# Phantom Files Configuration Reference

Default config path: `config/phantom.yaml` (production typically `/etc/phantom/phantom.yaml`).
Target environment: Linux only.

Relative paths in `paths` are resolved from the project root (directory that contains `pyproject.toml`), not from the current working directory.

## paths
- `logs_dir`: Log directory (audit and alert queue JSONL files live here).
- `traps_dir`: Root directory for deployed traps.
- `evidence_dir`: Local evidence storage directory.
- `templates`: Built-in templates directory.
- `user_templates_dir`: User-managed templates directory.
- `manifest`: Trap manifest path.
- `trap_registry_file`: Trap registry JSON file path.
- `policies`: Policies YAML path.

## templates
- `globals`: Key/value map injected into every template rendering.
- `datasets`: List of dataset files (YAML/JSON). Loaded in order and merged into the template context.

## sensors
- `driver`: `auto` | `ebpf` | `fanotify` | `inotify` (degraded).
- `ebpf_enabled`: Enable eBPF sensors.
- `ebpf_program`: Path to eBPF program for file sensor.
- `ebpf_poll_timeout_ms`: eBPF polling interval.
- `permission_timeout_ms`: fanotify permission timeout.
- `whitelist_process_names`: Process names that are treated as benign.
- `ignore_paths`: Path patterns to ignore.
- `inotify_pid_lookup`: Resolve PID via `lsof` in degraded mode (default: true).
- `inotify_pid_lookup_timeout`: `lsof` timeout seconds.
- `inotify_pid_lookup_min_interval`: Throttle interval between `lsof` runs.

## orchestrator
- `mode`: `active` | `observation` | `dry_run`.
- `worker_count`: Parallel workers.
- `event_queue_size`: Queue size for incoming events.
- `event_dedup_window`: Deduplication window (seconds).
- `orient_timeout`: Max time for analysis (seconds).
- `act_timeout`: Max time for response actions (seconds).
- `max_concurrent_actions`: Concurrency limit for response actions.
- `auto_execute`: Automatically execute actions.
- `min_severity`: Minimum severity to act on.
- `fail_close`: Deny by default on sensor timeouts.
- `degraded_timeout_block`: Immediate containment when degraded.
- `block_ttl_seconds`: TTL for process isolation.
- `ip_block_ttl_seconds`: TTL for IP blocks.

## forensics
- `timeout_seconds`: Max forensics collection time.
- `memory_dump`: Enable memory dump attempts.
- `chain_state_file`: Path to integrity chain state file.
- `s3.enabled`: Enable S3/MinIO uploads.
- `s3.endpoint_url`: S3/MinIO endpoint.
- `s3.region`: S3 region.
- `s3.bucket`: Bucket name.
- `s3.prefix`: Object prefix.
- `s3.access_key_env`: Env var for access key.
- `s3.secret_key_env`: Env var for secret key.
- `s3.encryption_key_env`: Base64 env var for AES-256-GCM key (must decode to 32 bytes). If invalid, uploads are aborted (fail-closed).
- `s3.verify_tls`: Verify TLS certs.
- `s3.object_lock_days`: Object Lock retention in days.
- `s3.upload_timeout_seconds`: S3 upload timeout.
- `pcap_precapture.enabled`: Enable pre/post packet capture.
- `pcap_precapture.interface`: Interface name (empty = auto).
- `pcap_precapture.ebpf_program`: Path to eBPF program for capture.
- `pcap_precapture.max_buffer_mb`: Ring buffer size.
- `pcap_precapture.min_memory_mb_for_precapture`: Minimum RAM to enable pre-capture.
- `pcap_precapture.pre_seconds`: Seconds before event.
- `pcap_precapture.post_seconds`: Seconds after event.
- `pcap_precapture.snaplen`: Packet snap length.
- `pcap_precapture.capture_ports`: Filter ports list.

## telemetry
- `process.collect_env`: Collect process environment variables (disabled by default).
- `process.env_allowlist`: Allowlist of env keys (optional).
- `process.env_denylist`: Denylist of env keys (overrides allowlist).
- `process.max_env_entries`: Maximum number of env entries captured.
- `process.max_env_value_len`: Max value length (truncated with `...`).

## signing
- `ed25519_private_key_path`: Path to Ed25519 private key.
- `ed25519_passphrase_env`: Env var with passphrase (optional).

## api
- `enabled`: Enable the API server.
- `bind`: Bind address.
- `port`: Listen port.
- `security_mode`: `api_key` | `jwt` | `both` | `mtls`.
- `api_key_env`: Env var for API key.
- `keys`: List of `{env, role}` entries for multi-key RBAC.
- `rate_limit_per_minute`: Per-IP rate limit.
- `tls_cert`: TLS certificate path.
- `tls_key`: TLS key path.

## integrations
- `webhook_urls`: Webhook endpoints.
- `syslog_enabled`: Enable syslog exporter.
- `syslog_address`: Syslog socket or host/port.
- `telegram_enabled`: Enable Telegram exporter.
- `telegram_bot_token_env`: Env var for bot token.
- `telegram_chat_id_env`: Env var for chat ID.

## rotation
- `enabled`: Enable trap rotation.
- `interval_seconds`: Rotation interval.
- `batch_size`: Number of traps to rotate per batch.
- `min_age_seconds`: Minimum file age before rotation.

## enforcement
- `allow_uid_fallback`: Allow UID-level network isolation if cgroup eBPF fails (disabled by default).

## sandbox
- `enabled`: Enable sandbox execution during forensics (enabled in sample config).
- `image`: Docker image for sandbox.
- `command`: Command executed in sandbox.
- `timeout_seconds`: Sandbox timeout.
- `network_disabled`: Disable container networking.
- `container_prefix`: Prefix for container names.

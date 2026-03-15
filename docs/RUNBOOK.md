# Phantom Files Daemon — Operations Runbook

## Quick Reference

| Action | Command |
|--------|---------|
| Start daemon | `systemctl start phantom` |
| Stop daemon | `systemctl stop phantom` |
| Reload config | `systemctl kill --signal=HUP phantom` |
| Check status | `systemctl status phantom` |
| View logs | `journalctl -u phantom -f` |
| Validate config | `phantomctl validate` |
| Production check | `phantomctl prod-check` |
| Bootstrap system | `sudo phantomctl bootstrap` |
| Change mode | `sudo phantomctl mode set <active\|observation\|dry-run>` |

## Installation

### From .deb package
```bash
sudo dpkg -i phantom-daemon_1.0.0_amd64.deb
sudo apt-get install -f  # resolve dependencies
```

### From .rpm package
```bash
sudo rpm -i phantom-daemon-1.0.0.x86_64.rpm
```

### From source
```bash
pip install -e .
sudo phantomctl bootstrap
```

## First-time Setup

1. **Bootstrap the system:**
   ```bash
   sudo phantomctl bootstrap
   ```
   Creates: phantom user/group, directories, RBAC groups.

2. **Configure secrets:**
   ```bash
   sudo vim /etc/phantom/secrets.env
   ```
   Required variables:
   - `PHANTOM_API_KEY` — API key for authentication
   - `PHANTOM_JWT_SECRET` — JWT signing key (min 32 chars)
   - `PHANTOM_TELEGRAM_BOT_TOKEN` — (optional) Telegram alerts
   - `PHANTOM_TELEGRAM_CHAT_ID` — (optional) Telegram chat ID

3. **Validate configuration:**
   ```bash
   phantomctl --config /etc/phantom/phantom.yaml validate
   ```

4. **Build sandbox image (if `sandbox.enabled`):**
   ```bash
   make build-image
   ```
   Or disable the sandbox in `config/phantom.yaml` if Docker is not available.

5. **Run production readiness check:**
   ```bash
   phantomctl prod-check
   ```

6. **Start the daemon:**
   ```bash
   sudo systemctl enable phantom
   sudo systemctl start phantom
   ```

## Operating Modes

| Mode | Behavior |
|------|----------|
| `active` | Full response: isolate, block, kill processes |
| `observation` | Monitor + collect forensics, no enforcement |
| `dry-run` | Log only, no enforcement, no forensics |

Change mode (requires root):
```bash
sudo phantomctl mode set observation
sudo systemctl kill --signal=HUP phantom  # apply without restart
```

**Warning:** Mode cannot be changed via API — only through CLI with root privileges.

## Monitoring

### Health endpoint
```bash
curl http://127.0.0.1:8787/health
```

### Prometheus metrics
```bash
curl http://127.0.0.1:8787/metrics
```

Key metrics:
- `phantom_http_requests_total` — HTTP request count by method/path/status
- `phantom_http_request_duration_seconds` — Request latency histogram
- `phantom_events_total` — Total processed events
- `phantom_sensor_degraded` — Sensor degradation flag (0/1)

### Logs
```bash
# Real-time logs
journalctl -u phantom -f

# Last 100 lines
journalctl -u phantom -n 100

# Audit log
tail -f /var/log/phantom/audit.jsonl

# Alert retry queue
tail -f /var/log/phantom/alert_queue.jsonl
```

## Incident Response

### Viewing incidents
```bash
curl -H "Authorization: Bearer $API_KEY" http://127.0.0.1:8787/api/v1/incidents
```

### Manual IP block
```bash
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "ip", "targets": ["1.2.3.4"], "ttl_seconds": 3600}' \
  http://127.0.0.1:8787/api/v1/blocks
```

### Manual process block
```bash
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"kind": "process", "targets": ["12345"]}' \
  http://127.0.0.1:8787/api/v1/blocks
```

## Troubleshooting

### Sensor degraded
If the sensor falls back to inotify:
1. Check kernel version: `uname -r` (need >= 5.10)
2. Check capabilities: `getpcaps $(pidof phantomd)`
3. Check if fanotify is available: `cat /proc/sys/fs/fanotify/max_user_marks`

### API not responding
1. Check if daemon is running: `systemctl status phantom`
2. Check port binding: `ss -tlnp | grep 8787`
3. Check firewall: `nft list ruleset`

### Evidence storage issues
1. Check disk space: `df -h /var/lib/phantom`
2. Check permissions: `ls -la /var/lib/phantom/evidence/`
3. Check S3 connectivity (if configured): check logs for S3 errors
4. If uploads stop after enabling encryption, verify `PHANTOM_EVIDENCE_KEY_B64` is valid (fail-closed)

### Hot-reload fails
1. Check SIGHUP delivery: `journalctl -u phantom | grep SIGHUP`
2. Validate new config first: `phantomctl validate`
3. Check for syntax errors in config/policies YAML files

## Backup & Recovery

### Backup
```bash
# Configuration
tar czf phantom-config-$(date +%Y%m%d).tar.gz /etc/phantom/

# Evidence
tar czf phantom-evidence-$(date +%Y%m%d).tar.gz /var/lib/phantom/evidence/
```

### Recovery
```bash
# Restore config
tar xzf phantom-config-YYYYMMDD.tar.gz -C /
chown -R phantom:phantom /etc/phantom/
chmod 0600 /etc/phantom/phantom.yaml /etc/phantom/secrets.env

# Restart
systemctl restart phantom
```

## Security Considerations

- API listens on `127.0.0.1` by default — use reverse proxy for external access
- Always use TLS in production (`api.tls_cert` / `api.tls_key` in config)
- Rotate API keys and JWT secrets periodically
- Evidence is encrypted with AES-256-GCM and signed with Ed25519
- Process environment collection is disabled by default; enable only with allowlists
- nftables rules managed by phantom — do not modify manually
- The daemon runs with minimal capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_KILL`

# Phantom Files — API Reference v1.0.0

Base URL: `http://127.0.0.1:8787`

## Authentication

All endpoints except `/health` and `/metrics` require authentication.

### API Key (Bearer token)
```
Authorization: Bearer <api-key>
```

### JWT
1. Obtain tokens via `POST /api/v1/auth/token` using API key
2. Use access token: `Authorization: Bearer <jwt-access-token>`
3. Refresh via `POST /api/v1/auth/refresh`

### Roles
| Role | Permissions |
|------|-------------|
| `admin` | Full access: incidents, blocks, templates, policies |
| `editor` | Read all, create incidents/templates |
| `viewer` | Read-only access |

---

## Endpoints

### Health & Metrics

#### `GET /health` | `GET /api/v1/health`
No authentication required.

**Response 200:**
```json
{
  "status": "ok",
  "sensor_mode": "fanotify+ebpf",
  "sensor_degraded": false,
  "sensor_reason": "",
  "precapture": {"status": "running"},
  "orchestrator": {
    "events_received": 42,
    "events_processed": 40,
    "mode": "active"
  }
}
```

#### `GET /metrics`
Prometheus format. No authentication required.

---

### Authentication

#### `POST /api/v1/auth/token`
Issue JWT token pair. Requires API key authentication.

**Request:**
```json
{"subject": "operator-1"}
```

**Response 200:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

#### `POST /api/v1/auth/refresh`
Refresh JWT tokens. Previous refresh token is revoked (rotation).

**Request:**
```json
{"refresh_token": "eyJ..."}
```

**Response 200:** Same as `/auth/token`.

---

### Incidents

#### `GET /api/v1/incidents`
List all incidents (sorted by `updated_at` descending).

**Response 200:**
```json
[
  {
    "incident_id": "INC-abc123",
    "trap_path": "/opt/phantom/traps/.aws/credentials",
    "process_pid": 1234,
    "process_name": "curl",
    "severity": "CRITICAL",
    "threat_category": "reconnaissance",
    "threat_score": 0.95,
    "event_count": 3,
    "actions": ["alert", "isolate_process", "collect_forensics", "kill_process"],
    "status": "open",
    "mode": "active"
  }
]
```

#### `GET /api/v1/incidents/{incident_id}`
Get incident by ID.

**Response 200:** Single incident object.
**Response 404:** `{"error": "not_found"}`

---

### Blocks

#### `GET /api/v1/blocks`
List active blocks.

#### `POST /api/v1/blocks`
Create a new block. **Requires admin role.**

**Request:**
```json
{
  "kind": "ip",
  "targets": ["1.2.3.4", "5.6.7.8"],
  "ttl_seconds": 3600
}
```

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `"ip"` or `"process"` | Block type |
| `targets` | `string[]` | IPs or PIDs |
| `ttl_seconds` | `int?` | Auto-expire (null = permanent) |

**Response 201:**
```json
{
  "block_id": "BLK-abc1234567",
  "kind": "ip",
  "targets": ["1.2.3.4"],
  "status": "active",
  "created_at": "2025-01-01T00:00:00+00:00",
  "expires_at": "2025-01-01T01:00:00+00:00"
}
```

---

### Templates

#### `GET /api/v1/templates`
List user templates.

#### `POST /api/v1/templates`
Add or activate template. **Requires admin/editor role.**

**Add template:**
```json
{
  "action": "add",
  "source": "/path/to/template.j2",
  "name": "custom_trap",
  "version": "v1.0.0"
}
```

**Activate template version:**
```json
{
  "action": "activate",
  "name": "custom_trap",
  "version": "v1.0.0"
}
```

---

### Policies

#### `GET /api/v1/policies`
Get current policies.

#### `POST /api/v1/policies`
Merge-update policies. **Requires admin role.**

**Request:**
```json
{
  "default": {
    "actions": ["alert", "collect_forensics", "block_network", "kill_process"]
  }
}
```

**Note:** `"mode"` key is forbidden — returns 403.

#### `PUT /api/v1/policies`
Replace all policies. **Requires admin role.**

---

## Error Responses

| Status | Meaning |
|--------|---------|
| 400 | Invalid request / JSON parse error / invalid_content_length |
| 401 | Authentication required |
| 403 | Forbidden (insufficient role or mode change attempted) |
| 404 | Resource not found |
| 413 | Request body too large (> 1 MB) |
| 429 | Rate limit exceeded |
| 501 | Feature not configured (e.g., JWT) |
| 503 | Service not available |

## Rate Limiting

Default: 60 requests/minute per IP (configurable via `api.rate_limit_per_minute`).

Health and metrics endpoints are exempt from rate limiting.

Response on limit exceeded:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{"error": "rate_limit_exceeded"}
```

## Request Size Limits

Maximum request body size: 1 MB. Invalid or negative `Content-Length` returns:
```json
{"error": "invalid_content_length"}
```

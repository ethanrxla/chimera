# Chimera Orchestrator API Surface (REST + SSE/WebSocket)

This document defines the minimal API surface to keep CLI and GUI behavior
locked together. All clients use the same endpoints and event stream.

Base URL: `/v1`

## Auth (MVP)

- Optional API key via `Authorization: Bearer <token>`.
- If omitted, the server runs in local/dev mode.

## REST Endpoints

### POST /v1/scope/parse

Parse + validate scope.

Request:
```json
{
  "scope_text": "yaml text",
  "filename": "scope.yml"
}
```

Response 200:
```json
{
  "scope_hash": "sha256",
  "warnings": ["missing rate limits"],
  "targets": [
    {"target": "https://example.com", "in_scope": true}
  ]
}
```

Errors: 400 invalid yaml, 422 invalid scope semantics.

### POST /v1/runs

Create a run.

Request:
```json
{
  "scope_text": "yaml text",
  "mode": "safe",
  "metadata": {"submitted_by": "user"}
}
```

Response 201:
```json
{
  "run_id": "run-20250101-abc123",
  "status": "created"
}
```

### GET /v1/runs/{run_id}

Get run status + plan summary.

Response 200:
```json
{
  "run_id": "run-20250101-abc123",
  "status": "running_tools",
  "started_at": "2025-01-01T12:00:00Z",
  "ended_at": null,
  "plan": {
    "task_count": 5,
    "tasks": [{"task_id": "T1", "tool": "net-utils", "target": "example.com"}]
  }
}
```

### POST /v1/runs/{run_id}/start

Starts execution for a created run (optional if auto-start on create).

Response 202:
```json
{"run_id": "run-20250101-abc123", "status": "running_tools"}
```

### POST /v1/runs/{run_id}/cancel

Cancel a run.

Response 202:
```json
{"run_id": "run-20250101-abc123", "status": "cancelled"}
```

### POST /v1/runs/{run_id}/approve

Handle approvals.

Request:
```json
{
  "approval_id": "approval-1",
  "decision": "allow",
  "notes": "approved by user"
}
```

Response 200:
```json
{"approval_id": "approval-1", "status": "approved"}
```

### GET /v1/runs/{run_id}/findings

Returns normalized findings.

Response 200:
```json
{
  "run_id": "run-20250101-abc123",
  "findings": [
    {
      "finding_id": "hash",
      "severity": "info",
      "title": "Subdomain Discovered",
      "affected_target": "mail.example.com",
      "evidence_refs": ["/artifacts/run-.../net-utils/T1/raw_output.txt"]
    }
  ]
}
```

### GET /v1/runs/{run_id}/artifacts/{path}

Fetch artifacts. Path is safe-joined under the run artifacts root.

Response 200: binary or text.

## Event Stream

Clients can consume events via SSE or WebSocket. Both streams emit the
same JSON envelope defined in `docs/design/event_schema.md`.

### SSE: GET /v1/runs/{run_id}/events

Query params:
- `cursor`: byte offset for replay (default `0`)

Stream format (SSE):
```
event: chimera
data: {"event_id":"...","run_id":"...","seq":1,"event_type":"run_created",...}

```

On reconnect, clients send the last cursor.

### WebSocket: /v1/runs/{run_id}/events/ws

Client sends:
```json
{"type":"subscribe","cursor":0}
```

Server sends:
```json
{"type":"event","data":{...event envelope...}}
```

## Event types (MVP)

Run lifecycle:
- `run_created`
- `run_finished`
- `run_failed`

Scope + planning:
- `scope_validated`
- `plan_created`

Execution:
- `task_started`
- `task_log`
- `task_finished`

Findings + artifacts:
- `artifact_saved`
- `finding_created`

Approvals:
- `approval_required`
- `approval_granted`
- `approval_denied`

## Error model (MVP)

All error responses use:
```json
{"error": {"code": "invalid_scope", "message": "Reason", "details": {}}}
```

HTTP status codes:
- 400 bad request
- 401 unauthorized
- 404 not found
- 409 conflict (e.g., run already started)
- 422 validation errors

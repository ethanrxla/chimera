# Chimera × HackerOne Hacker API v1

## Contract Surface (Hacker Mode)

### 0) Goals (what Chimera uses H1 for)

- Ingest scope for a program handle → produce a Chimera ScopeSpec for gating recon/scanners.
- Draft with Report Intents (AI-assisted, iterative) → attach evidence artifacts as you go.
- Submit final reports either via Report Intent submit or direct POST /hackers/reports.

### 1) Base URL, Versioning, Auth
#### 1.1 Base + version

Base: `https://api.hackerone.com/`

Versioned resources: `https://api.hackerone.com/v1/...`

#### 1.2 Authentication (HTTP Basic)

H1 uses HTTP Basic:

- `username` = API token identifier
- `password` = API token value
- Must be sent on every request.

Chimera requirement

Credentials come from env/secret-store (never logs):

- `H1_TOKEN_ID`
- `H1_TOKEN_VALUE`

### 2) Request/Response Shape (JSON:API-ish)

Most JSON endpoints use JSON:API-style envelopes:

`data: { type, id?, attributes, relationships? }`

List endpoints: `data: []`

Report intents + report submission follow this pattern.

### 3) Runtime Policy (rate limits, retries, idempotency)
#### 3.1 Rate limits (enforced by Runtime)

Documented limits:

- Read: 600/min (some report pages lower)
- Write: 25 per 20s

Chimera policy

- Put all H1 calls behind `Runtime.http(...)`
- Classify each request as:
    - `read` → `GET`/`HEAD`
    - `write` → `POST`/`PATCH`/`PUT`/`DELETE`
- Token bucket keyed by (`service=hackerone`, `class=read|write`)

#### 3.2 Retry policy

Treat these as retryable (with exponential backoff + jitter):

- `429`, `500`, `503` (and network timeouts)

Treat these as non-retryable without changing input/permissions:

- `400`, `401`, `403`, `404`, `422`

#### 3.3 Idempotency & event logging

Chimera should emit an `events.jsonl` record per call:

- `request`: method, path, query hash, body hash (not body), classification
- `response`: status, h1-request-id if present, timing, error detail

### 4) Scope Ingestion Contract (Program → ScopeSpec)
#### 4.1 Endpoint subset

Chimera needs structured scopes per program handle:

`GET /hackers/programs/{handle}/structured_scopes`

#### 4.2 Output: Chimera ScopeSpec (normalized)

Chimera should normalize H1 structured scopes into an internal schema, e.g.:

```json
{
  "program_handle": "example_program",
  "generated_at": "2026-01-03T21:00:00Z",
  "in_scope": [
    {
      "asset_identifier": "api.example.com",
      "asset_type": "domain|url|cidr|mobile_app|other",
      "max_severity": "critical|high|medium|low|none|unknown",
      "instructions": "string|null",
      "source": { "provider": "hackerone", "structured_scope_id": "12345" }
    }
  ],
  "out_of_scope": [
    {
      "asset_identifier": "admin.example.com",
      "reason": "Out of scope per program policy",
      "source": { "provider": "hackerone", "structured_scope_id": "67890" }
    }
  ]
}
```

#### 4.3 ScopeGate rule (hard requirement)

Adapters that touch the network must accept a `ScopeSpec` and must be blocked if:

- target not in `in_scope`
- target in `out_of_scope`
- ambiguous target (force manual allowlist)

This is the key “how it fits in Chimera”: H1 becomes the source of truth for what scanners are allowed to touch.

### 5) Report Intents Contract (drafting, attachments, submit)

Report intents are explicitly “draft reports developed using AI assistance,” designed for iterative workflows (perfect for Chimera).

#### 5.1 Endpoints (minimum viable set)

- `GET /hackers/report_intents` (list)
- `GET /hackers/report_intents/{id}` (details)
- `PATCH /hackers/report_intents/{id}` (update)
- `DELETE /hackers/report_intents/{id}` (delete)
- `POST /hackers/report_intents/{id}/submit` (submit draft as report)

Attachments:

- `GET /hackers/report_intents/{report_intent_id}/attachments`
- `POST /hackers/report_intents/{report_intent_id}/attachments`
- `DELETE /hackers/report_intents/{report_intent_id}/attachments/{id}`

#### 5.2 Report Intent object (fields Chimera should rely on)

From the Hacker Reference:

- `type`: `"report-intent"`
- `attributes` include at least:
    - `title`
    - `description`
    - `state` (e.g., `draft`)
    - `job status fields` like `has_failing_jobs`, etc.

#### 5.3 Update intent (PATCH) request shape

Example shown in docs:

```json
{
  "data": {
    "type": "report-intent",
    "attributes": {
      "description": "Updated writeup…"
    }
  }
}
```

Chimera mapping

- Chimera stores a canonical `FindingBundle` and materializes it into `description` (markdown)
- Keep “scanner evidence” as:
    - inline excerpts (short)
    - plus attachments for raw artifacts (screenshots, logs)

#### 5.4 Attachments (multipart)

Upload uses:

`POST /hackers/report_intents/{report_intent_id}/attachments`

`Content-Type: multipart/form-data`

Chimera mapping

- Any file in `artifacts/<run_id>/evidence/*` is eligible
- Store returned attachment IDs and expiring URLs in a local index: `artifacts/<run_id>/h1_attachments.json`

#### 5.5 Submit intent

`POST /hackers/report_intents/{id}/submit`

Chimera behavior

- After submit:
    - record the returned object (likely a report or confirmation payload)
    - “lock” the intent locally (no more destructive edits)

### 6) Direct Report Submission Contract (no intent path)

Even if you adopt intents as default, keep a direct submission path for simple flows:

#### 6.1 Endpoint

`POST /hackers/reports`

#### 6.2 Required payload attributes

Docs list required fields:

- `team_handle` (program handle)
- `title`
- `vulnerability_information`

Canonical Chimera submission payload

```json
{
  "data": {
    "type": "report",
    "attributes": {
      "team_handle": "example_program",
      "title": "Stored XSS in … via …",
      "vulnerability_information": "## Summary
...

## Steps to Reproduce
1...

## Impact
...

## Evidence
..."
    }
  }
}
```

### 7) Webhooks (optional, but clean for “report state sync”)

If you ever run Chimera as a “control plane” that reacts to new messages/status changes, use webhooks.

#### 7.1 Delivery headers

H1 sends:

- `X-H1-Event`
- `X-H1-Delivery` (unique GUID)
- `X-H1-Signature` (HMAC hexdigest of request body)

#### 7.2 Signature validation

- `SHA256 HMAC` over raw body with shared secret
- Compare against signature header using constant-time compare

Chimera mapping

- Treat `X-H1-Delivery` as idempotency key (store “seen deliveries”)

### 8) Chimera Module Design (what to implement)
#### 8.1 H1Client (pure HTTP)

Responsibilities:

- build URL paths
- apply Basic auth
- attach headers
- parse JSON envelopes
- expose `request(method, path, query, body, files)` but do not do rate limiting

All limits/retries belong to `Runtime`.

#### 8.2 HackerOneAdapter (workflow)
Methods (minimum)

- `sync_structured_scopes(program_handle) -> ScopeSpec`
- `list_report_intents()`
- `get_report_intent(id)`
- `update_report_intent(id, patch)`
- `upload_intent_attachments(id, files[])`
- `submit_report_intent(id)`
- `submit_report(team_handle, title, vulnerability_information)`

Files produced

- `chimera_state/programs/<handle>/scope_spec.json`
- `artifacts/<run_id>/h1_intent.json`
- `artifacts/<run_id>/h1_submission.json`

### 9) Default Chimera Flow (recommended)

1. `h1 sync --program <handle>`
   → fetch structured scopes → produce `ScopeSpec` → cache.
2. `scan --scope scope_spec.json`
   → recon/scanners run under `ScopeGate`
3. `h1 intent create|select` (if you add a create step; list+choose is enough to start)
4. `h1 intent update + upload attachments`
5. `h1 intent submit` OR `h1 report submit`

### What I didn’t include (on purpose)

- Customer/admin endpoints (program management, org members, etc.) because Chimera is “hacker mode” and those don’t belong in the default adapter surface.
- Giant object reference dumps—only the fields Chimera should depend on.
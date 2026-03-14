# Chimera Event Schema

This document defines the standardized schema for events emitted throughout the Chimera pipeline. These events provide an audit trail, enable real-time monitoring, and facilitate debugging and replay capabilities.

Events are designed to be JSON-serializable and are streamed locally (and eventually to Supabase).

## Core Event Structure

Every event adheres to the following structure:

```json
{
  "event_type": "string",       // A unique identifier for the type of event (e.g., "job_created", "task_started")
  "timestamp": "string",        // ISO 8601 formatted UTC datetime of when the event occurred (e.g., "2026-01-01T12:34:56.789Z")
  "job_id": "string",           // The unique ID of the job to which this event belongs
  "source": "string",           // The module or component that emitted the event (e.g., "orchestrator", "runner", "net-utils-adapter")
  "payload": { /* JSON object */ } // Event-specific data
}
```

## Common Event Types and Payloads

### `job_created`

Emitted when a new job is successfully created by the orchestrator.

*   **Source:** `orchestrator`
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "scope_hash": "string",
      "mode": "string",
      "scope_manifest_preview": { /* partial JSON representation of scope.yml */ }
    }
    ```

### `job_status_updated`

Emitted when the status of a job changes.

*   **Source:** `orchestrator`
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "old_status": "string",
      "new_status": "string"
    }
    ```

### `task_started`

Emitted when a specific task from the `ExecutionPlan` begins execution.

*   **Source:** `runner`
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "task_id": "string",
      "tool": "string",         // The tool associated with the task (e.g., "net-utils")
      "target": "string",       // The primary target for this task
      "options": { /* task-specific options */ }
    }
    ```

### `task_finished`

Emitted when a specific task completes execution.

*   **Source:** `runner`
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "task_id": "string",
      "status": "string",         // "completed", "failed", "cancelled"
      "duration_ms": "integer",
      "findings_count": "integer",
      "error_message": "string"   // Optional, if task failed
    }
    ```

### `finding_emitted`

Emitted when a new security finding is identified and normalized by an adapter.

*   **Source:** `runner` (after adapter normalization)
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "task_id": "string",      // The task that produced this finding
      "finding": { /* Full Finding schema as defined in data_models.md */ }
    }
    ```

### `artifact_saved`

Emitted when a raw output or evidence file is saved to persistent storage.

*   **Source:** `runner` (or adapter)
*   **Payload:**

    ```json
    {
      "job_id": "string",
      "task_id": "string",
      "artifact_id": "string",  // Unique ID or hash of the artifact
      "kind": "string",         // e.g., "raw_output", "screenshot", "report"
      "storage_ref": "string",  // Path to the artifact (e.g., local path, S3 URL)
      "meta": { /* content_type, size, checksum, etc. */ }
    }
    ```

### Future Event Types (Phase C/D)

*   `tool_selected`
*   `tool_configured`
*   `approval_required`
*   `approval_granted` / `approval_denied`
*   `rate_limit_hit`
*   `circuit_breaker_opened` / `circuit_breaker_closed`
*   `finding_deduplicated`

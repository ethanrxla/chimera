## Observable ZAP And Browser Automation

Goal: let Shannon-oracle and future agents drive ZAP and browser actions while the operator can observe execution live on the desktop.

### Current State

- Shannon already has an oracle tool loop that can call:
  - `hexstrike_probe`
  - `hexstrike_httpx`
  - `hexstrike_recon`
  - `hexstrike_endpoints`
  - `browser_navigate`
  - `browser_capture_dom`
  - `shell_run_scoped`
- Shannon browser tools currently run Playwright directly unless a mediated `BROWSER_TOOL_EXECUTOR` is injected.
- ZAP is currently integrated as a daemonized scanner via the ZAP API, not as an interactive desktop control surface.
- Chimera already exposes persistent browser sessions under `/v1/browser/sessions`, which is the best existing primitive for observable browser execution.

### Recommended Architecture

1. Keep ZAP as the scan/proxy engine.
2. Add a small mediated executor between Shannon and browser/ZAP actions.
3. Route Shannon oracle browser calls through that mediator instead of launching ad hoc headless Chromium instances.
4. Let the mediator either:
   - execute against Chimera browser sessions for visible Playwright control, or
   - execute against a local desktop-side extension/MCP server.
5. Store screenshots, HARs, DOM captures, and ZAP action logs as run artifacts.

### Why A Mediated Executor

- It gives one place to enforce scope, auth context, recording, and replay.
- It avoids invisible one-off Playwright launches inside the Shannon container.
- It makes "show me what the agent is doing" possible without rewriting Shannon's reasoning loop.
- It lets Burp/ZAP/operator workflows share the same browser session state.

### ZAP Automation Options

#### Option A: ZAP MCP Server

Build a `zap-mcp` service that exposes bounded tools such as:

- `zap_open_url`
- `zap_spider`
- `zap_ajax_spider`
- `zap_active_scan`
- `zap_list_alerts`
- `zap_export_report`
- `zap_set_context`
- `zap_exclude_patterns`

Pros:

- Fits the existing MCP usage pattern already present in the repo.
- Natural for agent tool-calling.
- Easy to keep scope enforcement centralized.

Cons:

- Still needs a browser mediator if the operator wants visible Playwright sessions.

#### Option B: Desktop Extension + Session Bridge

Build a local extension or host-side service that:

- talks to the Chimera browser session API
- optionally talks to local ZAP desktop or daemon API
- streams screenshots / current URL / console / network activity

Pros:

- Best operator visibility.
- Easier to attach to the user's real desktop/browser environment.

Cons:

- Harder to package than a pure container-side MCP server.

### Recommended Near-Term Build Order

1. Inject a mediated browser executor into Shannon so oracle browser tools can target Chimera browser sessions.
2. Add session streaming / screenshot polling to the UI so the operator can watch browser actions.
3. Build a minimal `zap-mcp` service for safe ZAP API actions.
4. Add an oracle tool set for ZAP actions after the mediator is stable.

### Minimal Tool Contract For A Future `zap-mcp`

Each tool should accept:

- `target` or `url`
- `context_name`
- `in_scope_only`
- `exclude_patterns`
- `max_duration_minutes`

Each tool should return:

- `status`
- `evidence_refs`
- `artifacts`
- `alerts`
- `raw_output_ref`

### Guardrails

- Enforce allowlist scope before every browser or ZAP call.
- Default to passive or bounded actions first.
- Keep active scan explicit and per-path.
- Never pass raw cookies or bearer tokens into general LLM context by default.
- Persist normalized request/response evidence separately from model prompts.

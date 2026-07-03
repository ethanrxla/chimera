# ZAP MCP Scaffold

This directory is the in-repo scaffold for a bounded ZAP MCP bridge.

Current state:
- Shannon already exposes bounded ZAP tools through its normal tool registry:
  - `zap_get_sites`
  - `zap_spider`
  - `zap_list_alerts`
- Chimera core already exposes matching proxied routes:
  - `POST /v1/zap/sites`
  - `POST /v1/zap/spider`
  - `POST /v1/zap/alerts`
- All of those calls run through the Chimera policy kernel with `tool="zap"`.

Why this directory exists:
- to reserve the repo location for a future standalone MCP server
- to keep the dependency board accurate for `P3.2`
- to document the bounded tool surface before adding more aggressive actions

Planned MCP surface:
- `zap_get_sites`
- `zap_spider`
- `zap_list_alerts`
- later: `zap_active_scan`

Guardrails for a future standalone service:
- allowlist-only targets
- passive and low-impact operations by default
- explicit policy deferral for active scan
- bounded timeouts and bounded result sizes
- artifact-oriented responses suitable for Shannon handoff

Relevant environment:
- `ZAP_BASE_URL`
- `ZAP_API_KEY`
- `SHANNON_ZAP_SPIDER_TIMEOUT_S`
- `SHANNON_ZAP_ALERT_LIMIT`
- `SHANNON_ZAP_SITE_LIMIT`
- `SHANNON_ZAP_POLL_INTERVAL_S`

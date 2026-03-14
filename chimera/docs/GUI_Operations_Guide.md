# GUI Operations Guide

## Screens

- Runs: load scope, plan, run
- Console: stream output + events
- Findings: filter by REPORT_READY
- Artifacts: open evidence and provenance
- Settings: API URL and run defaults

## Required Sequence

1. Paste or load scope YAML.
2. Run in fixture mode first.
3. Enable live mode + authorization + confirm token.
4. Start live run.
5. Review findings (REPORT_READY filter).
6. Export report packet.

## Safety Rules

- RUN disabled when scope not loaded or safety blocked.
- Replay mode only reads artifacts; no external execution.
- Promotions require evidence and provenance.

## Replay & Diff

- Select a baseline run and a replay run.
- Compare findings/promotions.
- Re-export report packet if new report-ready items appear.

## Troubleshooting

- API unreachable: check API URL and start core
- Scope hash mismatch: update scope and rerun plan
- Tool blocked: adjust SafetyPolicy allowlist


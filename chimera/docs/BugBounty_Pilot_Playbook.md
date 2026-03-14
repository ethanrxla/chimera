# Bug Bounty Pilot Playbook

## 1) Safety defaults (copy/paste config)

- Mode selection: start in fixture mode, move to live only after scope verification and explicit confirmation.
- Defaults:
  - max_workers: 2
  - rps: 5
  - timeout_s: 60
  - allow_destructive: false
- Tool allowlist: zypheron, vibepentester, decepticon
- Live confirm token: `I UNDERSTAND`

## 2) Target selection rules

- Start with 1 program and 1 asset.
- Prefer staging or designated test endpoints if in scope.
- Avoid login brute force, mass fuzzing, and credential stuffing.
- Do not target any asset marked out-of-scope or with explicit restrictions.

## 3) Run procedure (step-by-step)

1. Load scope YAML and verify it is current.
2. Run `/runs/plan` and confirm scope hash and task list.
3. Perform fixture run to validate adapters, parsing, and artifact storage.
4. If fixture is clean, set live confirm token.
5. Run live scan and monitor artifacts/events.
6. Review findings with REPORT_READY filter.
7. Generate report packet (manifest + provenance + evidence + report-ready findings).

## 4) Replay procedure

- When parsers or enrichers change, replay the original run.
- Verify that no external execution occurs.
- Diff old vs new findings and document changes.
- Update report packet if new report-ready items emerge.

## 5) Reporting rubric (HackerOne/Bugcrowd)

- Minimum evidence:
  - request/response or artifact evidence
  - clear reproduction steps
  - scope confirmation
- Reproduction steps template:
  1. Target: <url>
  2. Steps: <step-by-step>
  3. Observed: <evidence snippet>
- Impact statement template:
  - <user/data impact + conditions>
- Remediation guidance template:
  - <short fix suggestion + references>
- Do not report:
  - low confidence without evidence
  - issues without clear scope alignment
  - purely informational noise

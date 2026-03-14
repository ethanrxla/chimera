# Chimera — Master Execution Plan
### Production Readiness + 2026 Bug Bounty Competitive Edge
*Synthesized from: chimera_production_readiness_spec.md + DeepSeek analysis + architecture review*

---

## Strategic North Star

Chimera's competitive advantage is **not** finding more bugs. It is **proving exploit chains with artifacts, replay steps, and confidence scores**. The `provenance` and `report-ready` paths already in the codebase are the right foundation. Everything we build goes on top of that.

The goal: a researcher points Chimera at a scope, it discovers surface, generates hypotheses, validates them deterministically, chains low-severity findings into critical-impact proofs, and produces a triage-ready report with replay steps.

---

## What DeepSeek Got Right (Full Agreement)

- The fixed `autoswagger → strix → shannon` chain is the #1 bottleneck. It cannot branch.
- The findings model is too flat. It cannot represent chains, prerequisites, or escalation paths.
- Shannon is being used as a validator. It should only be used as a hypothesis generator and narrative writer.
- The existing tools (`vibepentester`, `zypheron`, `decepticon`) are underutilized. Don't build new scanners — wire up what exists.
- Don't add Rust to the core yet. The bottleneck is architecture, not performance.

## Where We Diverge (One Exception)

**Rust CLI is the right first Rust target.** DeepSeek says "don't add Rust yet" but their own matrix exempts CLI work. A Rust TUI:
- Is completely decoupled from the Python core
- Communicates with chimera-core via its existing FastAPI on port 8000
- Teaches the team Rust in a zero-risk context before touching performance-critical code
- Gives you the professional interface you want (ratatui-based, like a proper security tool)
- Can be built in parallel with Phase 1 Python work without blocking anything

This is the right call. Build the CLI in Rust. Build everything else in Python until you profile a real bottleneck.

---

## Phase Overview

| Phase | What | Language | Duration | Blocks |
|-------|------|----------|----------|--------|
| 0 | Git + chain verification | — | Day 1 | Everything |
| 1 | Evidence graph data model | Python | Days 1–4 | Phases 3, 4, 5 |
| 2 | Capability router | Python | Days 4–8 | Phase 3 |
| 3 | Typed validators (BOLA/auth/rate) | Python | Days 8–16 | Phase 5 |
| 4 | Rust CLI (parallel) | Rust | Weeks 1–3 | Nothing |
| 5 | Browser/DevTools + subdomain enum | Python + tool integration | Weeks 3–4 | Phase 6 |
| 6 | POC scaffolding + chain reporting | Python | Weeks 4–5 | — |

---

## Phase 0 — Git + Chain Verification
**Goal:** Safe baseline. Verify the existing chain actually works before touching anything.

### Git (already in progress)
```powershell
# Handle embedded tool repos as plain code
Remove-Item -Recurse -Force tools/autoswagger/.git
Remove-Item -Recurse -Force tools/chimera-net-utils/.git
Remove-Item -Recurse -Force tools/shannon/.git
Remove-Item -Recurse -Force tools/strix/.git
Remove-Item -Recurse -Force tools/vibe-pentester/.git
Remove-Item -Recurse -Force tools/zypheron/.git
Remove-Item -Recurse -Force tools/decepticon/.git
git add .
git commit -m "chore: initial commit - recovered project baseline"
# Then push to GitHub private repo
```

### Chain Verification Test
Before writing any new code, verify the existing chain produces output on a test target:
```bash
# Inside the running chimera-core container
docker exec -it chimera-core bash
# Run against a known safe target (your own server or a bug bounty lab)
python -m chimera_core run --scope test_scope.yml --dry-run
```

**Success criteria:** The chain completes without uncaught exceptions, produces at least one artifact in `/artifacts`, and the API responds at `http://localhost:8000/v1/health`.

---

## Phase 1 — Evidence Graph Data Model
**Goal:** Replace the flat findings model with one that can represent chains, prerequisites, and validation state.

### What to change
- `chimera/chimera-core/chimera_core/findings.py` — extend the finding model
- `chimera/chimera-core/chimera_core/modules/recon_gatherers/schemas.py` — add chain metadata
- `chimera/chimera-core/chimera_core/events.py` — add validation event types

### New data model (reference for Codex)
```python
# Target model — give this to Codex as the spec
class SecurityFinding:
    id: UUID
    finding_type: FindingType  # BOLA, BFLA, JWT, IDOR, XSS, etc.
    asset: Asset               # host, endpoint, parameter
    auth_context: AuthState    # what creds were active when found
    validation_status: ValidationStatus  # unvalidated, confirmed, false_positive
    confidence: float          # 0.0 - 1.0
    prerequisites: List[UUID]  # findings that enabled this one
    chain_parent_ids: List[UUID]  # findings this was chained from
    impact_path: List[ImpactStep] # how this escalates
    proof_artifacts: List[ArtifactRef]  # request/response pairs, screenshots
    sink: Optional[str]        # where the input lands (for XSS/injection)
    replay_steps: List[ReplayStep]  # deterministic reproduction steps
    # Keep existing fields for backward compat:
    title: str
    severity: Severity
    description: str
    evidence: str
    repro: str
```

### Codex Prompt — Phase 1
```
You are extending a Python security tool called Chimera (FastAPI + uvicorn, Python 3.13).

The current findings model is in chimera_core/findings.py. It has only: title, severity,
description, evidence, repro. This is too flat for exploit chain tracking.

Your task:
1. Extend the Finding model in findings.py to add these fields (all optional for
   backward compatibility):
   - finding_type: str (e.g. "BOLA", "BFLA", "JWT_NONE", "XSS_DOM", "IDOR")
   - asset: dict (host, endpoint, method, parameter)
   - auth_context: Optional[dict] (user_role, token_type, credentials_used)
   - validation_status: Literal["unvalidated", "confirmed", "false_positive", "needs_replay"]
   - confidence: float (0.0–1.0, default 0.5)
   - prerequisites: List[str] (UUIDs of findings that enabled this one)
   - chain_parent_ids: List[str] (UUIDs of findings this was chained from)
   - impact_path: List[dict] (list of {"step": str, "impact": str, "evidence": str})
   - proof_artifacts: List[dict] (list of {"type": "request"|"response"|"screenshot", "ref": str})
   - sink: Optional[str]
   - replay_steps: List[dict] (list of {"action": str, "request": dict, "expected_diff": str})

2. Update schemas.py in modules/recon_gatherers/ to add chain_metadata field to
   ReconFinding that links to the main finding ID.

3. Add new event types to events.py:
   - FindingValidated(finding_id, validation_status, confidence, validator_name)
   - ChainDiscovered(root_finding_id, chain_ids, combined_severity, impact_summary)
   - FalsePositiveRejected(finding_id, reason, validator_name)

4. All changes must be backward compatible — existing code that creates Finding
   objects without the new fields must continue to work.

5. Add a to_chain_summary() method to Finding that returns a human-readable
   string like: "IDOR on /api/users/{id} [confidence: 0.85] → enables AccountTakeover"

Run existing tests after changes: cd chimera-core && python -m pytest tests/unit/ -x -q
Fix any failures before finishing.
```

---

## Phase 2 — Capability Router
**Goal:** Replace the hardcoded `autoswagger → strix → shannon` chain with a capability registry that routes based on asset type and discovered context.

### What to change
- `chimera/chimera-core/chimera_core/planner.py` — the "placeholder" logic at line 40
- `chimera/chimera-core/chimera_core/orchestrator.py` — routing logic
- New file: `chimera_core/capabilities/registry.py`

### Codex Prompt — Phase 2
```
You are working on Chimera's planner (chimera_core/planner.py).

Currently the planner has hardcoded placeholder logic that always runs the same
autoswagger → strix → shannon chain regardless of the target.

Your task is to build a capability-driven router:

1. Create chimera_core/capabilities/registry.py with:

   CAPABILITY_REGISTRY = {
       "api_rest": ["autoswagger", "bola_validator", "rate_limit_validator"],
       "graphql": ["graphql_introspection", "graphql_batch"],
       "web_app": ["strix", "dom_xss_tracer", "prototype_pollution"],
       "subdomain": ["subfinder_adapter", "takeover_checker"],
       "llm_endpoint": ["prompt_injection_probe"],
       "auth": ["jwt_validator", "oauth_flow_checker"],
   }

   def get_capabilities_for_target(asset_type: str,
                                    discovered_context: dict) -> List[str]:
       """Returns ordered list of tool names to run for this asset type."""

2. Update planner.py to:
   - Detect asset type from scope (REST API, GraphQL, web app, subdomain list)
   - Query the capability registry for the right tool sequence
   - Emit a structured plan with stages: discover → classify → validate → chain → report
   - Fall back to the existing autoswagger → strix → shannon chain if asset type unknown

3. Update orchestrator.py to consume the structured plan from planner instead of
   the hardcoded sequence.

4. The existing tools that ARE registered in tools/registry.json but NOT used
   (vibepentester, zypheron, decepticon) should now be reachable through the
   capability router when their capability type is matched.

Keep all existing tests passing. Add tests for the new registry in
tests/unit/test_capability_registry.py
```

---

## Phase 3 — Typed Validators
**Goal:** Build the first deterministic validators. These prove/disprove findings, they don't generate them.

### Priority order
1. **BOLA/IDOR Validator** — replay request with different user credentials, compare responses
2. **Auth Comparator** — test endpoint with/without auth, detect exposed data
3. **Rate Limit Validator** — track state across requests, detect bypass
4. **JWT Validator** — test alg:none, weak secrets, audience issues

### Codex Prompt — Phase 3a (BOLA Validator)
```
You are building a BOLA/IDOR validator for Chimera (chimera_core/validators/).

A BOLA (Broken Object Level Authorization) validator works by:
1. Taking a confirmed endpoint + object ID from a prior finding
2. Making the same request with a different user's credentials
3. Comparing responses to detect unauthorized cross-user access

Create chimera_core/validators/bola_validator.py:

class BOLAValidator:
    """
    Deterministically proves or disproves BOLA/IDOR findings.
    Does NOT use LLMs. All validation is request/response comparison.
    """

    async def validate(self,
                       finding: Finding,
                       target_endpoint: str,
                       user_a_creds: dict,
                       user_b_creds: dict,
                       object_id: str) -> ValidationResult:
        """
        1. Request resource as user_a (owner): GET /api/users/{object_id}
        2. Request same resource as user_b (non-owner): GET /api/users/{object_id}
        3. Compare responses:
           - Same 200 response body = CONFIRMED BOLA
           - 403/404 for user_b = false positive, reject finding
           - Different response bodies = needs manual review
        4. Generate replay_steps artifact with both requests/responses
        5. Update finding.validation_status and finding.confidence
        6. Return ValidationResult with proof_artifacts
        """

class ValidationResult:
    status: Literal["confirmed", "false_positive", "inconclusive"]
    confidence: float
    proof_artifacts: List[dict]  # actual HTTP request/response pairs
    replay_steps: List[dict]
    explanation: str  # human-readable, not LLM-generated

Requirements:
- Use httpx for async HTTP
- Store raw request/response pairs as artifacts (headers, body, status)
- Calculate confidence based on: response code match, body similarity score,
  sensitive field presence
- Never call Shannon/LLM inside this validator
- Add tests in tests/unit/test_bola_validator.py with mock HTTP responses
```

---

## Phase 4 — Rust CLI (Parallel Track)
**Goal:** A professional TUI that controls Chimera via the FastAPI on port 8000. Built in Rust with ratatui. Can be developed at the same time as Phases 1–3.

### Architecture
```
chimera-cli (Rust/ratatui)
    │
    │  HTTP/WebSocket
    ▼
chimera-core (Python/FastAPI :8000)
    │
    ├── /v1/runs          POST: start scan, GET: list runs
    ├── /v1/runs/{id}     GET: run status, findings, artifacts
    ├── /v1/findings      GET: all findings with chain data
    ├── /v1/chain/{id}    GET: exploit chain visualization data
    └── /v1/replay/{id}   POST: replay a finding's proof steps
```

### TUI Layout (ratatui)
```
┌─ CHIMERA ──────────────────────────────────────────────────────┐
│ [S]can  [F]indings  [C]hain View  [R]eplay  [Q]uit            │
├─ Active Run ───────────────┬─ Findings ─────────────────────── │
│ target: api.example.com    │ [CRITICAL] BOLA /api/users/{id}   │
│ phase:  validate           │   chain: leaked_key → IDOR → ATO  │
│ tools:  bola_validator     │   confidence: 0.94                │
│ ████████░░░░ 67%           │ [HIGH] JWT alg:none /admin        │
│                            │   confidence: 0.88                │
├─ Event Stream ─────────────┴──────────────────────────────────  │
│ ✓ autoswagger: 47 endpoints discovered                        │
│ ✓ bola_validator: CONFIRMED cross-user object access          │
│ ⟳ jwt_validator: testing algorithm confusion...               │
└────────────────────────────────────────────────────────────────┘
```

### Codex Prompt — Phase 4 (Rust CLI)
```
Create a Rust TUI application called `chimera-cli` that controls a running
Chimera instance via HTTP.

Setup:
  cargo new chimera-cli

Dependencies (Cargo.toml):
  ratatui = "0.28"
  crossterm = "0.28"
  tokio = { version = "1", features = ["full"] }
  reqwest = { version = "0.12", features = ["json"] }
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"

The chimera-core API runs at http://localhost:8000/v1

Build a TUI with these views:

1. Dashboard view (default):
   - Top bar: active run target, current phase, tool being executed, progress bar
   - Left panel: live event stream (poll GET /v1/runs/{id}/events every 500ms)
   - Right panel: findings list sorted by severity (GET /v1/findings)
   - Each finding shows: severity badge, title, confidence score, chain summary

2. Chain View (press C):
   - Shows the exploit chain as ASCII art graph
   - Example: "leaked_key [low] → /admin/export [medium] → full_data_access [critical]"
   - Fetch from GET /v1/chain/{finding_id}

3. Replay View (press R on a finding):
   - Shows the exact HTTP requests that proved the finding
   - Request/response side by side
   - "Press ENTER to re-execute replay"

4. Scan launcher (press S):
   - Text input for target URL
   - Scope file path input
   - POST to /v1/runs to start

Key requirements:
- Async throughout (tokio)
- Graceful error handling if chimera-core is unreachable (show connection status)
- Color scheme: dark background, red=critical, orange=high, yellow=medium, green=info
- Keyboard navigation: arrow keys to select findings, Enter to expand
- ESC to go back, Q to quit

Start with the Dashboard view and event stream polling. The other views can be
stubbed as "coming soon" panels initially.
```

---

## Phase 5 — Browser/DevTools + Subdomain Enumeration

### Subdomain Enumeration
Integrate `subfinder` (Go tool) as a Chimera tool adapter. It runs as a subprocess inside the Docker container.

#### Codex Prompt — Subfinder Adapter
```
Create chimera_core/adapters/subfinder_adapter.py for subdomain enumeration.

The Docker container has subfinder available at /usr/bin/subfinder (add to Dockerfile).

class SubfinderAdapter:
    async def run(self, domain: str, scope: Scope) -> List[ReconFinding]:
        """
        1. Run: subfinder -d {domain} -silent -json
        2. Parse JSON output (each line is a JSON object)
        3. For each subdomain found:
           - Create ReconFinding with asset type "subdomain"
           - Check if subdomain resolves (DNS lookup)
           - Flag unresolved subdomains as potential takeover candidates
        4. Return list of ReconFindings
        """

Also update the Dockerfile (chimera/docker/core.Dockerfile) to install subfinder:
  RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ENV PATH="/root/go/bin:$PATH"

Add subfinder to the capability registry under "subdomain" capability type.
```

### Browser/DevTools Integration
Use Playwright inside the container for DOM inspection, network tab capture, and console monitoring.

#### Codex Prompt — Browser Adapter
```
Create chimera_core/adapters/browser_adapter.py using Playwright (already available
in many security tool containers, or add: pip install playwright && playwright install chromium).

class BrowserAdapter:
    """
    Headless Chrome with CDP access for client-side security testing.
    Captures: network requests, console errors, DOM state, page source.
    """

    async def analyze_page(self, url: str,
                           auth_cookies: Optional[dict] = None) -> BrowserFindings:
        """
        1. Launch Chromium headless with Playwright
        2. Intercept all network requests (page.on('request') / page.on('response'))
        3. Capture console messages (page.on('console'))
        4. Navigate to URL, wait for network idle
        5. Extract:
           - All outgoing API calls (method, URL, headers, body)
           - Console errors/warnings
           - Page source (page.content())
           - All script src URLs (for supply chain checks)
           - postMessage listeners (prototype pollution surface)
        6. Look for DOM XSS sinks:
           - innerHTML assignments
           - document.write calls
           - eval() usage
           - window.location changes from URL params
        7. Return BrowserFindings with all captured data as artifacts
        """

    async def trace_xss_sink(self, url: str,
                              parameter: str,
                              payload: str) -> ValidationResult:
        """
        Inject payload into URL parameter, check if it reaches a DOM sink.
        This is a VALIDATOR not a scanner - call it after a potential XSS is found.
        """

Update core.Dockerfile to install Playwright:
  RUN pip install playwright && playwright install chromium --with-deps
```

---

## Phase 6 — POC Scaffolding + Chain Reporting

### Codex Prompt — Chain Report
```
Update chimera_core/reporting.py to produce chain-aware reports.

Current report is just severity counts + flat findings list.

New report must include:

1. Executive Summary:
   - Number of confirmed exploit chains (not just individual findings)
   - Highest impact chain: "leaked_key → IDOR → full account takeover"
   - Total confirmed vs unvalidated vs rejected findings

2. Chain Graph (ASCII + JSON):
   For each chain (findings with chain_parent_ids), render:

   [LOW] API Key Leaked (/api/docs)
       └─► [MEDIUM] Privileged Endpoint Access (/admin/export)
               └─► [CRITICAL] Full Data Exfiltration (cross-tenant)
                   IMPACT: Complete account takeover, CVSS 9.8
                   CONFIDENCE: 0.94
                   REPLAY: 3 steps, all artifacts stored

3. Per-finding sections:
   - Validation status badge (CONFIRMED / UNVALIDATED / FALSE POSITIVE)
   - Replay steps (exact HTTP requests to reproduce)
   - Why it's exploitable (Shannon-generated narrative — LLM used here, correctly)
   - Proof artifacts (request/response pairs with sensitive data highlighted)

4. Rejected findings section:
   - List findings that were rejected by validators with reason
   - "Shows we're not a noisy scanner"

Use Shannon ONLY in step 3 "why it's exploitable" narrative. All structure
and chain logic must be deterministic Python, not LLM-generated.
```

---

## Rust Roadmap (After Phase 3 is Complete)

Once deterministic validators exist and you can profile real runs, here's when Rust makes sense:

| Component | When to add Rust | Why |
|-----------|-----------------|-----|
| CLI/TUI | Phase 4 (now) | Decoupled, zero risk, great UX |
| HTTP Replay Engine | After 1000+ req/s bottleneck is measured | Async, high throughput |
| Rate Limit Fuzzer | After auth validators work | CPU-bound state tracking |
| Token Cracker (JWT weak secrets) | After JWT validator is built in Python | Brute force is CPU-bound |
| Proxy/Interceptor | Future | Full traffic interception |

The proxy/interceptor is the biggest Rust opportunity long-term — a lightweight HTTP/HTTPS proxy (like a lightweight Burp) that feeds data directly into Chimera's evidence graph.

---

## Git Workflow Going Forward

After every session that produces working code:
```bash
git add chimera/chimera-core/
git commit -m "feat: <what you built>"
git push origin main
```

**Never** commit `.env`. Rebuild the lost day of changes as Phase 1 + Phase 4 sprint.

---

## What We're NOT Building (Per DeepSeek — Full Agreement)

- ❌ More scanners. Wire up what exists.
- ❌ LLM as validator. Shannon writes narratives only.
- ❌ GraphQL depth attacks before BOLA is proven.
- ❌ LLM prompt injection before API auth works.
- ❌ Supply chain checks before the evidence model exists.
- ❌ Rust in the core until Python validators are profiled and bottlenecks are measured.

---

## The One-Sentence Mission

> Chimera proves exploit chains with artifacts. It doesn't find more bugs — it proves the ones it finds.


# Chimera Agentic Pipeline Design

This document outlines the architecture of the Chimera agentic pipeline, a multi-stage process for automated security testing, driven by a Directed Acyclic Graph (DAG) of tasks.

## Pipeline Stages

The pipeline operates through the following stages, orchestrated by the `Orchestrator`:

1.  **Requirement Analysis → Scope Normalization:** Converts raw user input into a canonical internal scope representation.
2.  **Context Manager:** Establishes and maintains the stateful memory for the current run.
3.  **Tool Selection & Planning:** Selects appropriate tools and constructs an `ExecutionPlan` as a DAG of tasks.
4.  **AI Test Plan Generation (future):** Dynamically refines the `ExecutionPlan` based on context.
5.  **Automated Execution:** Executes the tasks defined in the `ExecutionPlan` safely and observably.
6.  **Results Analysis:** Normalizes, deduplicates, and triages findings.

---

### 1. Requirement Analysis → Scope Normalization

This stage is responsible for taking a user-defined scope manifest and converting it into a structured, canonical internal representation (`ScopeGraph`, `ScopePolicy`). This is the foundation for all ethical guardrails.

*   **Input:** User-provided `scope.yml` (allowlist, denylist, rate limits, credentials notes, proof-of-authorization).
*   **Process (`chimera_core.scope` module):**
    *   Parses the `scope.yml` into `ScopeGraph` and `ScopePolicy` objects.
    *   `ScopeGraph` uses efficient data structures (e.g., Trie for domains, Interval Set for CIDRs) for fast `is_in_scope` checks.
    *   `ScopePolicy` encapsulates general rules like `max_rps`, `max_concurrency`, and `allowed_methods`.
    *   Performs URL canonicalization to ensure stable target representation (e.g., scheme, case, trailing slash, default ports).
*   **Output:** `ScopeGraph`, `ScopePolicy`, and `scope_hash` (a stable identifier for the run's scope).

### 2. Context Manager

The `RunContext` (`chimera_core.context` module) serves as the stateful memory for the entire job run. It tracks information to prevent redundant work and ensures efficient resource utilization.

*   **Input:** `job_id` (from orchestrator).
*   **Process:** Initializes data structures to store:
    *   `VisitedURLSet`: Tracks canonical URLs that have already been processed (e.g., using a HashSet or Bloom filter).
    *   `HostStatsMap`: Stores per-host metrics like `rps tokens`, `error rate`, `last_seen` (for rate limiting and circuit breaking).
    *   `ArtifactIndex`: Maps artifact hashes to their storage references.
    *   `FindingDedupeIndex`: Maps finding hashes to their IDs for efficient deduplication.
*   **Output:** `RunContext` instance.

### 3. Tool Selection & Planning

This stage generates an `ExecutionPlan` (`chimera_core.planner` module) — a Directed Acyclic Graph (DAG) of `Task` objects. It strategically chooses the minimal set of tools (adapters) required for the given target type and test objectives.

*   **Input:** `ScopeGraph`, `ScopePolicy`, `RunContext`, user "intent" (e.g., API-only, web-only).
*   **Process:**
    *   **Planner Logic:** Uses capability-based routing. For example:
        *   If OpenAPI/Swagger is detected or explicitly in scope, schedule `Autoswagger` tasks.
        *   If a general web application is in scope, schedule `Strix` tasks. Strix has access to 19 HexStrike tool wrappers (nmap, nuclei, gobuster, sqlmap, dalfox, ffuf, katana, subfinder, httpx, nikto, …) and calls them directly during its agentic loop.
        *   Shannon tasks are scheduled after Strix. Shannon's executor stage has a live tool-call loop: it emits `<hexstrike_call>{"tool":"<name>","target":"<url>"}` blocks, the Shannon service dispatches them to HexStrike (port 8888), injects results back into the LLM context, and iterates up to `HEXSTRIKE_MAX_TOOL_TURNS` times (default 3) before producing findings.
    *   **DAG Construction:** Tasks are defined with dependencies, forming a DAG (Adjacency List + Indegree Map).
*   **Output:** `ExecutionPlan` (a DAG of `Task` objects).

### 4. AI Test Plan Generation (Future)

*(This stage is planned but not implemented in Phase A/B)*

This future stage will use AI to dynamically generate and refine the `ExecutionPlan` based on discovered context and prior findings, allowing for more adaptive and intelligent testing.

### 5. Automated Execution

The `Runner` (`chimera_core.runner` module) executes the `ExecutionPlan` safely, reproducibly, and observably. It acts as the interface between the orchestrator and the individual tool adapters.

*   **Input:** `ExecutionPlan`, `RunContext`, `event_sink`.
*   **Process:**
    *   **Scheduler (`chimera_core.scheduler` module):** Uses Kahn's algorithm (topological sort) to determine the execution order of tasks, respecting dependencies.
    *   **Worker Pool:** Executes ready tasks concurrently, respecting the `max_concurrency` defined in `ScopePolicy`.
    *   **Rate Limiting (Future):** Employs a Token Bucket algorithm per-host to enforce `max_rps` from `ScopePolicy`.
    *   **Circuit Breaker (Future):** Implements logic to temporarily stop hammering hosts that are erroring excessively.
    *   **Tool Adapter Invocation:** Calls the `run()` method of the selected tool adapters.
    *   **Partial-success handling:** If Strix exits non-zero but produced a `run.completed` event in `events.jsonl` or data rows in `vulnerabilities.csv`, the adapter treats it as `partial_success` rather than a hard failure. Only that task's downstream dependents are blocked; independent chains (browser, Shannon) continue.
    *   **Per-chain failure isolation:** On hard failure, only the failed task's transitive dependents are added to `blocked_chains`. Independent task chains are not halted.
    *   **Event Emission:** Emits structured events (`task_started`, `task_finished`, `finding_emitted`, `artifact_saved`, `task_warning`, `task_blocked`) to the `event_sink` for real-time tracking and auditability.
*   **Output:** Raw artifacts (tool outputs), structured event stream.

### 6. Results Analysis

This stage (`chimera_core.orchestrator` in collaboration with adapters) transforms raw tool outputs into standardized `Finding` objects and performs triage.

*   **Input:** Raw tool output from adapters.
*   **Process:**
    *   **Normalization Pipeline:** Each tool adapter's `normalize()` method (part of the formal adapter contract) parses its raw output into the unified `Finding` schema.
    *   **Strix finding deduplication:** The strix adapter merges findings whose titles share >50% Jaccard word overlap at the same severity+URL, keeping the richer description and unioning evidence refs.
    *   **Contradiction detection:** If `penetration_test_report.md` summary contradicts a finding (e.g. "robust against clickjacking" but a clickjacking vuln exists), the finding's confidence is downgraded to 0.3 and a `contradiction_note` is attached.
    *   **Shannon LLM oracle (stage after Strix):** Three-stage chain — planner (`qwen2.5-coder:7b`) drafts hypotheses, executor (`whiterabbitneo-13b`) calls HexStrike tools live to gather evidence (up to 3 tool turns), validator (`qwen2.5-coder:7b`) produces a final JSON findings array.
    *   **Global deduplication:** Uses the `FindingDedupeIndex` in `RunContext` to prevent reporting identical findings across different tools or runs.
    *   **Triage (Future):** Prioritizes findings by severity, confidence, or impact.
*   **Output:** Normalized `Finding` objects (stored in `Job.findings`), and suggested `next_actions` (future).

---

## Agentic Guardrails

Chimera is designed to be "agentic" but safe and deterministic, constrained by:

*   **ScopePolicy:** Enforces allowlist-only targeting and explicit denylists.
*   **Planner:** Only approved tools and tasks are scheduled.
*   **Runner:** Enforces rate limits, concurrency caps, and handles out-of-scope redirects.
*   **Audit Trail:** Every action is logged as a structured event.

This ensures a bug bounty-safe operation.
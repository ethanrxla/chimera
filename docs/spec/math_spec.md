# Chimera Mathematical Specification (Draft)

This document provides a discrete-math-first specification for Chimera’s core runtime guarantees:

- **Scope enforcement** (what targets may be acted on)
- **Execution planning** (task dependency graphs and scheduling constraints)
- **Event log semantics** (`events.jsonl` as the system-of-record)
- **Evidence graph** (how artifacts, findings, and provenance relate)
- **Invariants** (properties that must always hold)
- **Event → Graph update rules** (deterministic mapping from events to graph updates)
- **Testable properties** (property-based test ideas tied to the repo’s schema)

This is intentionally implementation-oriented: the definitions map to the current repo conventions (notably `artifacts/<run_id>/events.jsonl` and saved tool outputs).

---

## 1. Notation

- \(U\): universe of possible **targets** (domains, IPs, URLs, endpoints).
- \(R\): set of **run identifiers** (strings, e.g. UUIDs).
- \(T\): set of **tasks** (planner tasks) and **commands** (runtime invocations).
- \(A\): set of **artifacts** persisted under `artifacts/<run_id>/...`.
- \(F\): set of **findings** in `findings.json` (and related outputs).
- \(E\): set of **events** (lines in `events.jsonl`).
- \(G=(V, \mathcal{E})\): directed labeled evidence graph.
- For a JSON object `x`, `x.k` means field access.

---

## 2. Scope as a Set/Language Constraint

### 2.1 Scope manifest

A scope manifest is a mapping with (at minimum):

- `allowlist`: list of strings (domains, URLs, CIDRs, patterns)
- `denylist`: list of strings

Let each allow/deny entry denote a language over targets:

- For an entry \(p\), let \(L(p) \subseteq U\) be the set of targets matched by \(p\).

Define:

- \(A := \bigcup_{p\in allowlist} L(p)\)
- \(D := \bigcup_{q\in denylist} L(q)\)

### 2.2 In-scope predicate

\[
InScope(x) := (x \in A) \wedge (x \notin D)
\]

### 2.3 Scope enforcement invariant (runtime)

Let `Targets(cmd)` be the set of targets extracted from a runtime command invocation.

\[
\forall cmd \in T,\ \forall x \in Targets(cmd):\ InScope(x)
\]

This is the *non-negotiable* safety property. Any violation must result in a hard error and an explicit event + artifact trail.

---

## 3. Execution Plans as DAGs (Task Graph)

Chimera’s execution plan can be modeled as a directed acyclic graph (DAG).

- Tasks \(T=\{t_1,\dots,t_n\}\)
- Dependencies \(\mathcal{D} \subseteq T\times T\)
  - \((t_i,t_j)\in \mathcal{D}\) means **\(t_j\) depends on \(t_i\)**.

### 3.1 DAG constraint

\[
(T,\mathcal{D})\ \text{must be acyclic}
\]

### 3.2 Feasible schedule constraints

Let \(start(t)\) and \(end(t)\) denote task start/end times in a schedule.

Precedence:
\[
\forall (u,v)\in \mathcal{D}:\ start(v) \ge end(u)
\]

Resource/concurrency constraints (abstract form):
\[
\forall \tau:\ \sum_{t\ \text{running at}\ \tau} r(t) \le R_{max}
\]

Rate limiting (abstract form):
\[
\text{requests/sec} \le \lambda
\]

---

## 4. Event Log Semantics (`events.jsonl`)

### 4.1 Canonical event envelope

In Chimera, `events.jsonl` is a sequence of JSON objects (one per line). The canonical envelope used by the runtime includes:

- `event_id`: string
- `run_id`: string
- `seq`: integer (monotone increasing per run)
- `event_type`: string
- `timestamp`: ISO8601 string
- `source`: string
- `payload`: object

Let each event be \(e \in E\). Define:

- `Run(e) := e.run_id`
- `Seq(e) := e.seq`
- `Type(e) := e.event_type`
- `Payload(e) := e.payload`

### 4.2 Event ordering invariants

For each run \(r \in R\), consider the subsequence \(E_r = [e \in E \mid Run(e)=r]\) in file order.

Monotone sequence numbers:
\[
\forall i < j:\ Seq(E_r[i]) < Seq(E_r[j])
\]

Stable run id:
\[
\forall e \in E_r:\ Run(e)=r
\]

### 4.3 Minimum event vocabulary (current runtime behavior)

This repo currently emits (at least) events similar to:

- `cmd_started` with `payload.command` and `payload.task_id`
- `artifact_saved` with `payload.path` and `payload.stream` (stdout/stderr)
- `output_truncated` for large outputs
- task-level events such as `task_executing`, `task_succeeded`, `task_failed`
- `shannon_oracle` (used as a high-level signal that an oracle response occurred)

The spec below defines update rules for these types and allows unknown event types to be ignored or logged without breaking invariants.

---

## 5. Artifacts and Artifact Kinds

Artifacts live under:

- `artifacts/<run_id>/...`

Command outputs are conventionally written to:

- `artifacts/<run_id>/commands/<task_id>/stdout.txt`
- `artifacts/<run_id>/commands/<task_id>/stderr.txt`

The API infers artifact kinds from filename conventions (examples):

- `stdout.txt` → `stdout`
- `stderr.txt` → `stderr`
- `run_manifest.json` → `run_manifest`
- `provenance.json` → `provenance`
- `notes.md` → `analysis_notes`
- `*.md` / `*.json` → typically report-like outputs

Define `Kind(a)` as the inferred kind of artifact `a`.

---

## 6. Evidence Graph \(G\)

### 6.1 Node types

Let the graph be \(G=(V,\mathcal{E})\) with typed nodes:

- \(V = V_{run} \cup V_{event} \cup V_{artifact} \cup V_{task} \cup V_{finding} \cup V_{asset}\)

Where:

- Run node: \(v_r \in V_{run}\) for each run id \(r\)
- Event node: \(v_e \in V_{event}\) for each event \(e\)
- Artifact node: \(v_a \in V_{artifact}\) for each persisted artifact path
- Task node: \(v_t \in V_{task}\) for each `task_id`
- Finding node: \(v_f \in V_{finding}\) for each stable finding id (see `findings.json`)
- Asset node: \(v_x \in V_{asset}\) for each target/asset id (domain/url/ip/endpoint)

### 6.2 Edge labels (core relations)

Edges are labeled relations; at minimum:

- `HAS_EVENT`: run → event
- `NEXT`: event → event (adjacent in sequence)
- `EMITS_ARTIFACT`: event → artifact
- `HAS_TASK`: run → task
- `TASK_STARTED_BY`: task → event
- `TASK_PRODUCED`: task → artifact
- `EVIDENCE_FOR`: artifact → finding
- `TARGETS`: (task or finding or artifact) → asset

The exact set can grow, but the invariants below must remain satisfiable.

---

## 7. Event → Graph Update Rules

This section defines deterministic transformation rules that build/update the evidence graph from the event log and artifact filesystem.

### 7.1 Base rule: ingest every event

For each event \(e\) with `run_id = r`:

- Ensure run node \(v_r\) exists.
- Create event node \(v_e\) keyed by `event_id` (or file offset if needed).
- Add edge \(v_r \xrightarrow{HAS\_EVENT} v_e\).
- If this is not the first event for the run, link previous event \(v_{e'} \xrightarrow{NEXT} v_e\) (by file order).

### 7.2 `cmd_started`

Given an event \(e\) where `Type(e) = "cmd_started"` and:
- `Payload(e).task_id = tid` (may be null/empty)
- `Payload(e).command = [c0, c1, ...]`

Rules:

- Ensure task node \(v_{tid}\) exists if `tid` is present.
- Add edge \(v_r \xrightarrow{HAS\_TASK} v_{tid}\).
- Add edge \(v_{tid} \xrightarrow{TASK\_STARTED\_BY} v_e\).

Target extraction (spec-level):

- Let `Targets(command)` be the set of arguments that parse as URLs/domains/IPs (consistent with the runtime’s heuristic extractor).
- For each \(x \in Targets(command)\), ensure asset node \(v_x\) exists and add:
  - \(v_{tid} \xrightarrow{TARGETS} v_x\)

### 7.3 `artifact_saved`

Given `Type(e) = "artifact_saved"` and:
- `Payload(e).path = p` (absolute or run-relative path)
- optional `Payload(e).task_id = tid`
- optional `Payload(e).stream ∈ {stdout, stderr}`

Rules:

- Ensure artifact node \(v_a\) exists for normalized artifact id (recommend using run-relative path).
- Add edge \(v_e \xrightarrow{EMITS\_ARTIFACT} v_a\).
- If `tid` exists, ensure task node exists and add:
  - \(v_{tid} \xrightarrow{TASK\_PRODUCED} v_a\)

### 7.4 `output_truncated`

Given `Type(e) = "output_truncated"`:

- Attach metadata to the related task/artifact nodes if identifiable (e.g., stream, original_bytes, kept_bytes).
- The key invariant is that truncation is **explicit** and therefore testable.

### 7.5 Finding ingestion (`findings.json`)

Findings are not guaranteed to be events today; they are persisted artifacts.

On run completion (or periodically), ingest `artifacts/<run_id>/findings.json` if present:

- For each finding record \(f\):
  - Create finding node \(v_f\) keyed by its stable id (see API stable-id rules).
  - For each evidence reference (file path or URL):
    - If it resolves to an artifact path, link artifact → finding:
      - \(v_a \xrightarrow{EVIDENCE\_FOR} v_f\)
    - If it is a URL/endpoint, create asset node and link finding → asset:
      - \(v_f \xrightarrow{TARGETS} v_x\)

---

## 8. Invariants (Must Always Hold)

### 8.1 Scope invariants

**I-SCOPE-1 (No out-of-scope execution)**:
\[
\forall cmd\_started\ e:\ \forall x \in Targets(Payload(e).command):\ InScope(x)
\]

If a target cannot be verified (DNS failure, parse failure), the runtime may allow execution *only* if the scope policy explicitly permits the category (e.g., private IPs), otherwise it must fail closed.

### 8.2 Event log invariants

**I-EVENT-1 (Monotone seq per run)**:
\[
\forall r,\ \forall i<j:\ Seq(E_r[i]) < Seq(E_r[j])
\]

**I-EVENT-2 (Run-local consistency)**:
\[
\forall e\in E_r:\ e.run\_id=r
\]

### 8.3 Artifact invariants

**I-ART-1 (Artifacts referenced by events exist)**:
\[
\forall e\in E,\ Type(e)=artifact\_saved \Rightarrow \exists a\in A:\ a.path = Payload(e).path
\]

**I-ART-2 (Stdout/stderr artifacts are bounded or explicitly truncated)**:

For each command, the system must ensure either:
- `stdout.txt`/`stderr.txt` sizes are ≤ `max_output_bytes`, **or**
- an `output_truncated` event exists for that stream.

### 8.4 Provenance invariants

**I-PROV-1 (Artifacts have provenance)**:
\[
\forall a\in A,\ \exists e\in E:\ (e \xrightarrow{EMITS\_ARTIFACT} a)
\]

(If you later add “out-of-band” artifacts, they must be accompanied by explicit provenance records.)

---

## 9. Testable Properties (Property-Based Tests)

This section describes properties that can be checked using Hypothesis (Python) or proptest (Rust).
The intent is to make Chimera’s guarantees *falsifiable* and regression-proof.

### 9.1 Generators (inputs)

Generate:

- **Scope manifests**: random allow/deny patterns + concrete targets.
- **Command arguments**: lists that include URLs/domains/IPs and non-target tokens.
- **Event streams**: sequences of valid event envelopes with randomized `event_type`, `payload`, `seq`, and optional truncation markers.
- **Artifact trees**: temporary directories shaped like `artifacts/<run_id>/commands/<task_id>/{stdout.txt,stderr.txt}`.

### 9.2 Properties tied to actual schema

**P-EVENT-SEQ (Monotone seq)**:
- Given any generated event log for a run that is emitted via the event sink, `seq` must be strictly increasing in file order.

**P-ARTIFACT-SAVED-EXISTS**:
- For any event log containing `artifact_saved` events, the referenced paths must exist on disk.
  - If the runtime writes artifacts after emit, the property becomes “event must be emitted only after write+fsync” (preferred).

**P-OUTPUT-BOUNDS-OR-TRUNCATED**:
- For any executed command:
  - if `stdout.txt` (or `stderr.txt`) exceeds `max_output_bytes`, there must exist an `output_truncated` event for that stream.

**P-SCOPE-FAIL-CLOSED**:
- For any command whose extracted targets include at least one out-of-scope element, execution must not proceed and must yield:
  - a deterministic exception (or error return)
  - an event that records the violation (recommended: `scope_violation`)

**P-GRAPH-CONSTRUCTION-CONSISTENCY**:
- Build evidence graph \(G\) from `events.jsonl` + artifacts directory:
  - Every `artifact_saved` event must correspond to an `EMITS_ARTIFACT` edge.
  - Every run must have a `HAS_EVENT` chain with `NEXT` edges matching file order.

**P-FINDINGS-EVIDENCE-ANCHORS**:
- For any synthesized `findings.json` where evidence refs point to existing artifact paths, graph ingestion must produce `EVIDENCE_FOR` edges.

### 9.3 Where tests should live (repo conventions)

- Unit/property tests for runtime invariants: `chimera/chimera-core/tests/unit/`
- Integration tests that touch the filesystem artifacts layout: `chimera/chimera-core/tests/integration/`
- Property-based tests can be added alongside existing unit tests; prefer small, fast checks (no network).

---

## 10. Practical Next Steps (Engineering)

If you want this spec to directly enhance Chimera’s MVP:

- Add explicit event types for:
  - `scope_violation`
  - `cmd_finished` (with duration + exit code + artifact paths)
  - `llm_started` / `llm_finished` (with artifact refs for prompt/response)
- Add a graph builder module (pure function):
  - Input: `events.jsonl`, `findings.json`, artifact root
  - Output: graph in a simple JSON format
- Add the property tests in §9 to lock in invariants and prevent regressions.


---

## 11. Shannon Auto-Probe Pipeline (Implementation Note)

The Shannon oracle now runs a 4-stage chain instead of 3:

```
Stage 1  Planner  (qwen2.5-coder:7b, temp=0.0)
         Input:  prior strix findings + scope allowlist
         Output: {"checks": [{id, class, target, evidence_basis}]}
         Rule:   Only generates checks for endpoints present in evidence.
                 Returns {"checks":[]} if no evidence.

Stage 1.5  Auto-Probe  (Chimera/Python, no LLM)
         For each check, dispatches the best HexStrike tool:
           broken_auth / IDOR / SSRF → httpx  (-title -status-code -tech-detect)
           XSS                        → dalfox (--silence --no-color)
           SQLi / injection           → nuclei  (tags=sqli, severity=high,critical)
         Scope-gated: probes only URLs whose hostname appears in the query scope section.
         Per-probe timeout: SHANNON_PROBE_TIMEOUT_S (default 90s).

Stage 2  Executor  (qwen2.5-coder:7b, temp=0.1)
         Input:  {query, plan, probe_results}
         Output: {"findings": [...]} — ONLY when probe_results show concrete evidence.
         Rule:   target field must be exact probed URL, never "unknown".

Stage 3  Validator  (qwen2.5-coder:7b, temp=0.0)
         Input:  {query, findings}
         Output: deduplicated + severity-checked findings
```

**Invariant (I-SHANNON-1):** A Shannon finding with no probe_result entry must not appear in Stage 3 output.

**Model configuration:**
- All three stages use `qwen2.5-coder:7b` to avoid Ollama model-swap overhead.
- `OLLAMA_KEEP_ALIVE=300s` keeps the model warm for the duration of a typical run.
- `mirostat=2` + `num_ctx=24576` passed via Ollama extra_body for output quality.

# Chimera Development Plan: Building the Agentic Spine

## 1. Mission Overview

This document outlines the high-level plan for the next phase of Chimera's development, based on the provided architectural principles. The core methodology is **Test-Driven Development (TDD)**, focusing on building a robust, safe, and observable "spine" for the agent before integrating real security tools.

The guiding principle is to build the system from the "spine" outward, ensuring every layer is validated by tests before features are added.

## 2. Core Architectural Principles (The "Spine" Contracts)

The entire system will be built upon a set of core data structures and contracts that ensure safety, determinism, and efficiency.

*   **ScopePolicy:** Provides fast allow/deny checks for targets.
    *   **DS/Algo:** Utilizes Hash Sets for exact domain matching, a Trie (or suffix tree) for efficient subdomain checking, and Interval Sets for IP/CIDR ranges.
*   **ExecutionPlan (DAG):** Represents tasks and their dependencies.
    *   **DS/Algo:** Implemented as an Adjacency List and Indegree Map to enable scheduling via Topological Sort (e.g., Kahn's Algorithm).
*   **RunContext:** Manages stateful memory for a run, preventing loops and redundant work.
    *   **DS/Algo:** Employs a Hash Set for visited URLs, a Hash Map for host statistics, and a Token Bucket algorithm per-host for rate limiting.
*   **EventLog:** An append-only stream for auditing and observability.
    *   **DS/Algo:** Uses a Queue/Buffer for offline event sinking and stable content hashes for idempotent writes.
*   **FindingIndex:** Manages the deduplication of findings.
    *   **DS/Algo:** A Hash Map where the key is a stable hash of `(vulnerability_type + target + key_evidence)`.

---

## 3. Development Phases

### Phase A: Build and Test the Spine

This phase focuses exclusively on creating the core infrastructure, validated by a comprehensive test suite. **No real tool adapters will be written in this phase.**

*   **Task 1: Establish Testing Infrastructure**
    *   Create `tests/unit` and `tests/fixtures` directories inside `chimera/chimera-core`.
    *   Add `pytest` and `pytest-cov` to `chimera/chimera-core/requirements.txt`.

*   **Task 2: Implement and Test the Core Spine (TDD)**
    *   **Scope Logic (`scope.py`):**
        *   **Test 1: Allowlist Logic:** Test that `example.com` correctly allows `sub.example.com` but blocks `evil.com`.
        *   **Test 2: Denylist Precedence:** Test that a deny rule for `admin.example.com` overrides an allow rule for `example.com`.
        *   **Test 3: URL Canonicalization:** Test that URLs are stably normalized (e.g., `https://Example.com/` becomes `https://example.com`).
    *   **Scheduler Logic (`scheduler.py`):**
        *   **Test 4: Dependency Respect:** Test that a task B dependent on task A never runs before A is complete.
        *   **Test 5: Concurrency Limiting:** Test that with a worker pool of N, no more than N tasks run concurrently.
    *   **Event Logic (`events.py`):**
        *   **Test 6: Event Emission Order:** Test that a task emits events in the correct order (`task_started` -> `task_finished`) and that payloads are valid JSON.

*   **Task 3: Create a CLI Smoke Test**
    *   Add a `chimera smoke-test` command to `cli.py`.
    *   This test will validate file system permissions, DNS resolution, and basic module imports within the containerized environment.

### Phase B: Integrate First Tool - Autoswagger (TDD)

With a fully tested spine, we will integrate our first real tool.

*   **Methodology:**
    1.  Create `tests/fixtures/autoswagger/` with sample raw output files.
    2.  Write adapter tests **first**.
    3.  Implement the `AutoswaggerAdapter`.
*   **Adapter Tests:**
    *   **Scope Enforcement:** The adapter must refuse to run on an out-of-scope target.
    *   **Safe Command Generation:** The adapter must build a command-line string that includes the correct rate limits and safety flags.
    *   **Normalization:** The adapter must correctly parse the fixture output into a list of standardized `Finding` objects ("golden fixture" testing).

### Phase C: Integrate Agentic Core - Strix (TDD)

The same TDD pattern will be applied to integrate the more complex `Strix` agent.

*   **Methodology:**
    1.  Create fixtures for Strix output.
    2.  Write adapter tests for scope safety and normalization.
    3.  Implement the `StrixAdapter`.
    4.  Develop end-to-end integration tests against a local, containerized test application.

---

This plan establishes a clear, test-driven path forward. The immediate next steps will be to execute **Phase A**, starting with the setup of the testing infrastructure.

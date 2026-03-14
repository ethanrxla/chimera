# Chimera MVP Stack

This document outlines the recommended "Minimum Viable Product" (MVP) stack for a Chimera prototype. The goal is to select a minimal set of tools that provide broad coverage for bug bounty workflows without creating redundancy.

## Recommended Tools

The following tools are recommended for the initial implementation of Chimera:

1.  **Autoswagger:** An API specialist tool.
2.  **Strix:** An agentic core for general web application testing.
3.  **Shannon:** An optional, gated tool for deep web exploitation.

---

### 1. Autoswagger (API Specialist)

*   **Role:** Specialist for testing APIs, particularly those with OpenAPI/Swagger specifications.
*   **Capabilities:**
    *   Discovery of OpenAPI/Swagger endpoints.
    *   Checks for authentication and authorization weaknesses in APIs.
*   **When to use:** Use when the scope includes API base URLs or known `swagger.json` / `openapi.json` endpoints.

### 2. Strix (Agentic Core)

*   **Role:** The default "agentic core" for Chimera.
*   **Capabilities:**
    *   Bundles a toolkit for proxying, browser automation, reconnaissance, and code analysis.
    *   Supports different scan modes and has a regular release cadence.
*   **When to use:** Use for general web application testing and workflow automation. Strix should be the primary tool for tasks that are not specifically assigned to a specialist.

### 3. Shannon (Optional Validator)

*   **Role:** A specialist tool for high-confidence validation of vulnerabilities through exploitation.
*   **Capabilities:**
    *   Built to "prove by exploitation" in web applications.
*   **Licensing:** AGPL-3.0. This is an important consideration if Chimera is offered as a service.
*   **When to use:**
    *   Use when you need high-confidence validation of a vulnerability.
    *   Should be used in a controlled mode with strict guardrails.
    *   Should be explicitly enabled by the user due to its nature and licensing.

## Cloning Decision Rule

When adding new tools to the Chimera pipeline, use the following decision rule: clone a new tool's repository only if it answers one of these questions:

*   "Is this our core agent runner?" (e.g., Strix)
*   "Is this our API auth specialist?" (e.g., Autoswagger)
*   "Is this our high-confidence validator (gated)?" (e.g., Shannon)

Avoid adding tools that overlap with the responsibilities of the core runner. Any other tools should be parked until the pipeline has normalized outputs and logging.

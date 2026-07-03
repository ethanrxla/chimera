# Tool Routing Logic

Chimera uses a capability-based routing approach to tool selection. Instead of running every tool, the "Tool Selection & Configuration" stage of the pipeline selects the best tool for each task. This document outlines the decision engine for this process.

## Guiding Principle

The core principle of tool routing in Chimera is to use a specialist tool when a task matches its capabilities, and to use the "agentic core" for all other tasks. This ensures that the most effective tool is used for each job, while minimizing redundancy.

## Suggested Routing Logic

The following is the current routing table for the Chimera stack:

| Task Type                   | Condition                                                     | Tool to Use                                                             |
| --------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **API Testing**             | Scope includes API base URLs or swagger endpoints.            | `Autoswagger`                                                           |
| **General Web App Testing** | The task involves general web app testing.                    | `Strix` (agentic core) — calls HexStrike tools during testing           |
| **Reconnaissance**          | The task involves passive/active recon.                       | `Strix` via `hexstrike_recon`, `hexstrike_subfinder`, `hexstrike_httpx` |
| **Network Scanning**        | Port/service discovery needed.                                | `Strix` via `hexstrike_nmap`                                            |
| **Vulnerability Scanning**  | Known-CVE or misconfiguration checks.                         | `Strix` via `hexstrike_nuclei`                                          |
| **Directory Brute-Force**   | Hidden path/endpoint discovery.                               | `Strix` via `hexstrike_gobuster` or `hexstrike_ffuf`                    |
| **SQL Injection**           | SQLi testing on forms or URL parameters.                      | `Strix` via `hexstrike_sqlmap`                                          |
| **XSS Testing**             | Cross-site scripting fuzzing.                                 | `Strix` via `hexstrike_dalfox`                                          |
| **Browser Automation**      | The task requires JS-rendered DOM interaction.                | `Strix` (browser capability) or `hexstrike_katana`                      |
| **Deep Verification**       | LLM oracle verifies a hypothesis with active HexStrike calls. | `Shannon` — executor emits `<hexstrike_call>` blocks (up to 3 turns)   |
| **Code Analysis**           | The task requires code analysis.                              | `Strix` (agentic core)                                                  |

### HexStrike Tool Categories (available to Strix and Shannon)

| Category         | Tools                                                               |
| ---------------- | ------------------------------------------------------------------- |
| **Recon**        | `hexstrike_recon`, `hexstrike_subfinder`, `hexstrike_httpx`, `hexstrike_waybackurls`, `hexstrike_gau` |
| **Web crawl**    | `hexstrike_endpoints`, `hexstrike_katana`                           |
| **Vuln scan**    | `hexstrike_nuclei`, `hexstrike_nikto`, `hexstrike_wpscan`           |
| **Brute-force**  | `hexstrike_gobuster`, `hexstrike_ffuf`                              |
| **Injection**    | `hexstrike_sqlmap`, `hexstrike_dalfox`                              |
| **Network**      | `hexstrike_nmap`                                                    |
| **Auth**         | `hexstrike_jwt_analyzer`, `hexstrike_probe`                         |
| **LLM analysis** | `hexstrike_attack_surface`, `hexstrike_exploit_guidance`            |
| **Arbitrary**    | `hexstrike_command` (escape hatch for any tool in the container)    |

## Experimental and Research Tools

Tools below are not wired into the primary pipeline:

*   **Decepticon:** Multi-agent autonomous red teaming framework — experimental only.
*   **Zypheron-CLI:** CLI aggregator; overlaps with Strix + HexStrike responsibilities.
*   **VibePenTester:** Lightweight standalone scanner; not suitable as orchestration backbone.

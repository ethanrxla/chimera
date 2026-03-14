# Tool Routing Logic

Chimera uses a capability-based routing approach to tool selection. Instead of running every tool, the "Tool Selection & Configuration" stage of the pipeline selects the best tool for each task. This document outlines the decision engine for this process.

## Guiding Principle

The core principle of tool routing in Chimera is to use a specialist tool when a task matches its capabilities, and to use the "agentic core" for all other tasks. This ensures that the most effective tool is used for each job, while minimizing redundancy.

## Suggested Routing Logic

The following is a suggested routing table for the Chimera MVP stack:

| Task Type                  | Condition                                           | Tool to Use                                |
| -------------------------- | --------------------------------------------------- | ------------------------------------------ |
| **API Testing**            | Scope includes API base URLs or swagger endpoints.  | `Autoswagger`                              |
| **General Web App Testing**| The task involves general web app testing.          | `Strix` (the agentic core)                 |
| **Reconnaissance**         | The task involves reconnaissance.                   | `Strix` (the agentic core)                 |
| **Browser Automation**     | The task requires browser automation.               | `Strix` (the agentic core)                 |
| **Code Analysis**          | The task requires code analysis.                    | `Strix` (the agentic core)                 |
| **Deep Web Exploitation**  | The user has explicitly enabled high-confidence validation. | `Shannon` (the optional validator)         |

## Experimental and Research Tools

There are several other agent frameworks and tools that were considered but are not part of the MVP stack. These tools should only be used for research and experimentation, not as part of the primary production pipeline.

*   **Decepticon:** A multi-agent autonomous red teaming framework. It can be used for experimenting with different agent architectures.
*   **Zypheron-CLI:** A CLI aggregator for security testing. It may provide unique scanners that could be wrapped by Chimera, but it overlaps with the responsibilities of the agentic core.
*   **VibePenTester:** A packaged scanner with a simple web UI. It can be a source of ideas for a UI, or used as a lightweight single-scan option, but it is not suitable as an orchestration backbone.

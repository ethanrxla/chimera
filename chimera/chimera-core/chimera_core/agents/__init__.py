"""
Chimera Autonomous Agent System.

Provides multi-turn LLM-driven agents capable of autonomous vulnerability
discovery and exploitation.  Each agent gets a specialist prompt, a set of
scope-enforced tools, and a turn/token budget.

Providers:
    - AnthropicProvider  → Claude Sonnet / Opus (best quality, paid)
    - OpenAIProvider     → GPT-4o / NVIDIA NIM / Ollama (OpenAI-compatible)

Core loop:
    AgentLoop orchestrates the multi-turn conversation, feeding tool results
    back to the LLM until the budget is exhausted or the agent terminates.
"""

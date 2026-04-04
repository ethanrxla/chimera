"""
Shannon Security Gateway — minimal FastAPI service for AI-powered security
verification at the end of the Chimera pipeline.

It preserves the narrow Chimera contract while allowing multiple LLM backends:
- Anthropic Messages API
- OpenAI-compatible chat completion endpoints (vLLM, TGI gateways, Ollama, etc.)

API contract (matches chimera_core/adapters/shannon_adapter.py):
  GET  /health
  POST /api/v1/tasks   {"query": "...", "session_id": "..."}  → {"task_id": "..."}
  GET  /api/v1/tasks/{task_id}                                → {"status": "...", "findings": [...]}
"""

import asyncio
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List

import anthropic
from fastapi import FastAPI, HTTPException
from openai import AsyncOpenAI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Shannon Security Gateway")

# In-memory task store (single-process, sufficient for the Chimera use case)
_tasks: Dict[str, Dict[str, Any]] = {}

PROVIDER = (os.getenv("SHANNON_PROVIDER") or "anthropic").strip().lower().replace("-", "_")
if PROVIDER == "openai":
    PROVIDER = "openai_compatible"
MODEL = (
    os.getenv("SHANNON_MODEL")
    or (
        "claude-sonnet-4-6"
        if PROVIDER == "anthropic"
        else "WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
    )
).strip()
MAX_TOKENS = int(os.getenv("SHANNON_MAX_TOKENS") or "8096")
TEMPERATURE = float(os.getenv("SHANNON_TEMPERATURE") or "0.1")
OPENAI_BASE_URL = (os.getenv("SHANNON_OPENAI_BASE_URL") or "http://sec-llm:8000/v1").rstrip("/")
OPENAI_API_KEY = (
    os.getenv("SHANNON_OPENAI_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or "dummy"
)

SYSTEM_PROMPT = """You are an expert penetration tester performing the final verification pass in an automated security pipeline.

You will receive:
- Target URL(s)
- Optionally: prior findings from automated tools (strix crawler, browser DOM analysis, etc.)
- Vulnerability categories to check

Your job:
1. Verify and enrich each prior finding — confirm severity, add precise repro steps
2. Look for exploit chains (e.g. IDOR + weak auth = full account takeover)
3. Identify high-value issues the automated tools typically miss (business logic, auth flow, privilege escalation)
4. Provide proof-of-exploit steps that a pentester can execute immediately

Return ONLY a valid JSON object — no markdown, no explanation, no code blocks:
{
  "findings": [
    {
      "title": "Short descriptive title",
      "description": "What the vulnerability is and why it matters",
      "severity": "critical|high|medium|low",
      "target": "affected URL",
      "method": "GET|POST|PUT|DELETE or null",
      "parameter": "vulnerable parameter name or null",
      "repro_guidance": "Step-by-step proof of exploit"
    }
  ]
}

If nothing actionable is found, return: {"findings": []}"""


class TaskRequest(BaseModel):
    query: str
    session_id: str = ""


@app.get("/health")
def health():
    payload = {
        "status": "ok",
        "service": "shannon-gateway",
        "provider": PROVIDER,
        "model": MODEL,
    }
    if PROVIDER == "openai_compatible":
        payload["base_url"] = OPENAI_BASE_URL
    return payload


@app.post("/api/v1/tasks")
async def submit_task(req: TaskRequest):
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "running",
        "findings": [],
        "provider": PROVIDER,
        "model": MODEL,
    }
    asyncio.create_task(_run_analysis(task_id, req.query))
    logger.info("Task %s submitted (session=%s)", task_id, req.session_id)
    return {"task_id": task_id, "status": "running"}


@app.get("/api/v1/tasks/{task_id}")
def get_task(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, **task}


async def _run_analysis(task_id: str, query: str) -> None:
    try:
        logger.info("Task %s: calling provider=%s model=%s", task_id, PROVIDER, MODEL)
        text = await _generate_response_text(query)
        data = json.loads(_coerce_json_object(text))
        findings: List[Dict[str, Any]] = data.get("findings", [])
        _tasks[task_id] = {
            "status": "completed",
            "findings": findings,
            "provider": PROVIDER,
            "model": MODEL,
        }
        logger.info("Task %s completed with %d findings", task_id, len(findings))

    except json.JSONDecodeError as exc:
        logger.error("Task %s JSON parse error: %s", task_id, exc)
        _tasks[task_id] = {
            "status": "failed",
            "error": f"JSON parse error: {exc}",
            "findings": [],
            "provider": PROVIDER,
            "model": MODEL,
        }
    except Exception as exc:
        logger.error("Task %s failed: %s", task_id, exc)
        _tasks[task_id] = {
            "status": "failed",
            "error": str(exc),
            "findings": [],
            "provider": PROVIDER,
            "model": MODEL,
        }


async def _generate_response_text(query: str) -> str:
    if PROVIDER == "anthropic":
        return await _generate_anthropic_response(query)
    if PROVIDER == "openai_compatible":
        return await _generate_openai_compatible_response(query)
    raise RuntimeError(
        "Unsupported SHANNON_PROVIDER. Expected 'anthropic', 'openai', or 'openai_compatible'."
    )


async def _generate_anthropic_response(query: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    client = anthropic.AsyncAnthropic(api_key=api_key)
    message = await client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": query}],
    )
    return _extract_text_content(message.content)


async def _generate_openai_compatible_response(query: str) -> str:
    client = AsyncOpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
    response = await client.chat.completions.create(
        model=MODEL,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
    )
    if not response.choices:
        raise RuntimeError("OpenAI-compatible backend returned no choices")
    return _extract_text_content(response.choices[0].message.content)


def _extract_text_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
                continue
            text = getattr(item, "text", None)
            if text:
                parts.append(str(text))
        return "\n".join(part.strip() for part in parts if part).strip()

    text = getattr(content, "text", None)
    if text:
        return str(text).strip()

    raise RuntimeError("LLM response did not include text content")


def _coerce_json_object(text: str) -> str:
    cleaned = text.strip()

    if "```" in cleaned:
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if fenced:
            cleaned = fenced.group(1).strip()
        else:
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    if not cleaned.startswith("{"):
        obj_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if obj_match:
            cleaned = obj_match.group(0)

    return cleaned

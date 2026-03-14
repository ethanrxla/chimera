from __future__ import annotations

import json
from typing import Any, Dict, Optional

import httpx


def response_artifact(label: str, response: httpx.Response) -> Dict[str, Any]:
    request = response.request
    return {
        "type": label,
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": request.content.decode("utf-8", errors="ignore") if request.content else "",
        },
        "response": {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
        },
    }


def similarity_score(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    left_tokens = set(left.split())
    right_tokens = set(right.split())
    if not left_tokens or not right_tokens:
        return 0.0
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    return len(left_tokens & right_tokens) / len(union)


def try_json(value: str) -> Optional[Any]:
    try:
        return json.loads(value)
    except Exception:
        return None

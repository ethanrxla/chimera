from __future__ import annotations

from typing import Any, Dict, List, Optional


def heuristic_oracle(question: str, *, target: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, object]:
    lowered = question.lower()
    suggestions: List[Dict[str, object]] = []
    if "graphql" in lowered:
        suggestions = [
            {"vector": "graphql_introspection", "reason": "Schema leakage via introspection remains a common foothold."},
            {"vector": "graphql_batching", "reason": "Batching can bypass per-request controls."},
            {"vector": "graphql_depth", "reason": "Deep nesting can trigger authorization or DoS paths."},
        ]
    elif "jwt" in lowered or "token" in lowered:
        suggestions = [
            {"vector": "jwt_alg_none", "reason": "Reject unsigned tokens deterministically."},
            {"vector": "jwt_weak_secret", "reason": "Weak HMAC secrets still appear in bug bounty APIs."},
            {"vector": "jwt_kid_confusion", "reason": "Key selection confusion can yield signature bypass."},
        ]
    elif "xss" in lowered or "browser" in lowered or "dom" in lowered:
        suggestions = [
            {"vector": "dom_reflection", "reason": "Check whether user input reaches `innerHTML` or `document.write`."},
            {"vector": "postmessage_surface", "reason": "Message listeners often lack origin validation."},
            {"vector": "prototype_pollution", "reason": "Client-side merges can expose sink execution."},
        ]
    else:
        suggestions = [
            {"vector": "auth_context_review", "reason": "Map tokens, roles, and cross-user deltas first."},
            {"vector": "rate_limit_validation", "reason": "Missing throttling escalates otherwise medium issues."},
            {"vector": "exploit_chain_review", "reason": "Look for prerequisite findings that can be chained."},
        ]

    answer_lines = [f"Target: {target or 'unspecified'}", "Possible attack vectors:"]
    for idx, suggestion in enumerate(suggestions, start=1):
        answer_lines.append(f"{idx}. {suggestion['vector']}: {suggestion['reason']}")
    if context:
        answer_lines.append(f"Context keys: {', '.join(sorted(context.keys())[:8])}")

    return {
        "question": question,
        "target": target,
        "answer": "\n".join(answer_lines),
        "suggestions": suggestions,
    }

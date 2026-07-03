from __future__ import annotations

from typing import Any

from chimera_core.hexstrike.schemas import HttpResponseSummary


def extract_summary_fields(summary: HttpResponseSummary | dict[str, Any] | Any) -> tuple[int, dict[str, str], str]:
    if isinstance(summary, dict):
        return (
            int(summary.get("status_code", 0)),
            {str(k): str(v) for k, v in (summary.get("headers") or {}).items()},
            str(summary.get("body_excerpt") or ""),
        )
    if isinstance(summary, HttpResponseSummary):
        return summary.status_code, dict(summary.headers), summary.body_excerpt
    return 0, {}, ""


def default_evidence_refs(result: Any) -> list[str]:
    return [
        getattr(result, "request_artifact_ref", ""),
        getattr(result, "response_artifact_ref", ""),
        getattr(result, "normalized_artifact_ref", ""),
    ]

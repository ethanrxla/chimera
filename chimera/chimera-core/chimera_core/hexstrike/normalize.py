from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

from chimera_core.findings import Finding, stable_finding_id


def normalize_tool_output(tool_name: str, raw_data: Dict[str, Any], *, run_id: str, scope_hash: str) -> List[Finding]:
    if tool_name == "probe":
        return _normalize_probe(raw_data, run_id=run_id, scope_hash=scope_hash)
    if tool_name == "nuclei":
        return _normalize_nuclei(raw_data, run_id=run_id, scope_hash=scope_hash)
    return []


def _normalize_probe(raw_data: Dict[str, Any], *, run_id: str, scope_hash: str) -> List[Finding]:
    endpoint = str(raw_data.get("endpoint") or raw_data.get("target") or "unknown")
    checks = raw_data.get("checks") or {}
    findings: List[Finding] = []
    if checks.get("csp") is False or not checks.get("x_frame"):
        title = "Missing anti-clickjacking protections"
        findings.append(
            Finding(
                finding_id=stable_finding_id(title, endpoint, "hexstrike"),
                severity="medium",
                title=title,
                description="Endpoint is missing CSP frame controls or X-Frame-Options.",
                affected_target=endpoint,
                tool_source="hexstrike",
                tool_version="hexstrike-unified",
                run_id=run_id,
                scope_hash=scope_hash,
                timestamps=datetime.now(timezone.utc),
                finding_type="CLICKJACKING",
                asset={
                    "host": urlparse(endpoint).hostname or endpoint,
                    "endpoint": urlparse(endpoint).path or "/",
                    "method": "GET",
                    "parameter": None,
                },
                confidence=0.68,
            )
        )
    return findings


def _normalize_nuclei(raw_data: Dict[str, Any], *, run_id: str, scope_hash: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in raw_data.get("results", []):
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        title = str(info.get("name") or "Nuclei Finding")
        target = str(item.get("matched-at") or item.get("host") or "unknown")
        severity = str(info.get("severity") or "medium").lower()
        findings.append(
            Finding(
                finding_id=stable_finding_id(title, target, "hexstrike", str(item.get("template-id") or "")),
                severity=severity,
                title=title,
                description=str(item.get("template-id") or ""),
                affected_target=target,
                tool_source="hexstrike",
                tool_version="hexstrike-unified",
                run_id=run_id,
                scope_hash=scope_hash,
                timestamps=datetime.now(timezone.utc),
                finding_type=_infer_type(title),
                asset={
                    "host": urlparse(target).hostname or target,
                    "endpoint": urlparse(target).path or "/",
                    "method": "GET",
                    "parameter": None,
                },
                confidence=0.8 if severity == "high" else 0.65,
            )
        )
    return findings


def _infer_type(title: str) -> str:
    lowered = title.lower()
    if "xss" in lowered:
        return "XSS"
    if "idor" in lowered or "bola" in lowered:
        return "IDOR"
    if "sql" in lowered or "inject" in lowered:
        return "SQLI"
    return "WEB_FINDING"

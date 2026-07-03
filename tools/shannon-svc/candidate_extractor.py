from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


def _path_from_url(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


def _status_from_result(result: Dict[str, Any]) -> int | None:
    value = result.get("status_code")
    if isinstance(value, int):
        return value
    return None


def _looks_like_octopus_user_apikey_collection(endpoint: str) -> bool:
    parts = [part for part in endpoint.split("/") if part]
    return len(parts) == 4 and parts[:2] == ["api", "users"] and parts[3] == "apikeys" and parts[2].startswith("Users-")


def _result_text(result: Dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("title", "body_excerpt", "raw_output_excerpt", "excerpt", "detail"):
        value = result.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    checks = result.get("checks")
    if isinstance(checks, dict):
        parts.append(str(checks))
    return "\n".join(parts).lower()


def _candidate(
    *,
    claim_type: str,
    method: str,
    endpoint: str,
    title: str,
    target_url: str,
    evidence_refs: List[str],
    success_condition: str,
    verifier_hint: str,
    authenticated: bool = False,
    role: str = "anonymous",
    params: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "claim_type": claim_type,
        "target": {
            "method": method,
            "endpoint": endpoint,
            "params": params or None,
            "headers": None,
            "body": None,
        },
        "title": title,
        "evidence_refs": evidence_refs,
        "auth_context": {
            "authenticated": authenticated,
            "role": role,
            "session_fixed": authenticated,
        },
        "success_condition": success_condition,
        "verifier_hint": verifier_hint,
        "target_url": target_url,
    }


def extract_candidates_from_tool_results(*, intent: str, tool_results: List[Dict[str, Any]], targets: List[str]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for index, tool_call in enumerate(tool_results, start=1):
        if not isinstance(tool_call, dict):
            continue
        tool_name = str(tool_call.get("tool_name") or "")
        result = tool_call.get("result")
        if not isinstance(result, dict):
            continue
        result_view = result.get("summary") if isinstance(result.get("summary"), dict) else result

        evidence_refs = [f"agent_tool_call:{index}"]
        if result.get("artifact_ref"):
            evidence_refs.append(str(result.get("artifact_ref")))
        target_url = str(result_view.get("url") or result_view.get("target") or result_view.get("final_url") or result_view.get("endpoint") or "")
        endpoint = _path_from_url(target_url) if target_url else "/"
        status = _status_from_result(result_view)
        text_blob = _result_text(result_view)

        if tool_name == "browser_navigate" and target_url:
            if _looks_like_octopus_user_apikey_collection(endpoint) and status == 200:
                key = ("idor", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="idor",
                            method="GET",
                            endpoint=endpoint,
                            title=f"Cross-user API key collection exposure at {endpoint}",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition="Use an authenticated low-privilege session to compare access to the victim user's API key collection against sibling user resources and confirm inconsistent authorization.",
                            verifier_hint="probe_idor",
                            authenticated=True,
                            role="authenticated",
                        )
                    )
            elif endpoint == "/api/octopusservernodes" and status == 200:
                key = ("admin_exposure", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="admin_exposure",
                            method="GET",
                            endpoint=endpoint,
                            title="Infrastructure node inventory exposed to low-privilege user",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition="Confirm that an authenticated low-privilege user can access infrastructure node metadata that should be restricted to administrative roles.",
                            verifier_hint="probe_admin_access",
                            authenticated=True,
                            role="authenticated",
                        )
                    )
            if endpoint in {"/admin", "/rest/admin"} and status == 200:
                key = ("admin_exposure", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="admin_exposure",
                            method="GET",
                            endpoint=endpoint,
                            title=f"Admin surface exposed at {endpoint}",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition=f"Load {endpoint} anonymously and confirm admin functionality or admin-only surface.",
                            verifier_hint="probe_admin_access",
                        )
                    )
            elif endpoint in {"/openapi.json", "/graphql", "/swagger-ui.html", "/swagger"} and status == 200:
                key = ("api_surface_exposure", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="api_surface_exposure",
                            method="GET",
                            endpoint=endpoint,
                            title=f"API surface exposed at {endpoint}",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition=f"Fetch {endpoint} and confirm it exposes API schema or interactive API surface.",
                            verifier_hint="probe_api_surface",
                        )
                    )
            elif endpoint.startswith("/rest/basket/") and status in {200, 401, 403}:
                key = ("idor", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="idor",
                            method="GET",
                            endpoint=endpoint,
                            title=f"Potential IDOR on {endpoint}",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition="Change the basket identifier and determine whether another user's basket can be accessed.",
                            verifier_hint="probe_idor",
                        )
                    )
            elif endpoint == "/rest/user/whoami" and status == 200:
                key = ("auth_missing", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="auth_missing",
                            method="GET",
                            endpoint=endpoint,
                            title="Identity endpoint accessible without authentication",
                            target_url=target_url,
                            evidence_refs=evidence_refs + [f"http_status:{status}"],
                            success_condition="Confirm whether identity or user context is exposed without authentication.",
                            verifier_hint="probe_auth_missing",
                        )
                    )

        if tool_name == "hexstrike_endpoints":
            for endpoint_url in result_view.get("endpoints") or []:
                if not isinstance(endpoint_url, str):
                    continue
                endpoint = _path_from_url(endpoint_url)
                if endpoint in {"/openapi.json", "/graphql", "/swagger-ui.html", "/swagger"}:
                    key = ("api_surface_exposure", endpoint)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="api_surface_exposure",
                            method="GET",
                            endpoint=endpoint,
                            title=f"API surface exposed at {endpoint}",
                            target_url=endpoint_url,
                            evidence_refs=evidence_refs,
                            success_condition=f"Fetch {endpoint} and confirm it exposes API schema or interactive API surface.",
                            verifier_hint="probe_api_surface",
                        )
                    )

        if tool_name in {"hexstrike_probe", "browser_capture_dom", "hexstrike_nuclei", "hexstrike_dalfox", "hexstrike_attack_surface", "hexstrike_exploit"}:
            target_url = target_url or (targets[0] if targets else "")
            endpoint = endpoint if endpoint and endpoint != "/" else _path_from_url(target_url)
            if any(marker in text_blob for marker in ("xss", "alert(1)", "<svg", "onerror")):
                key = ("xss", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="xss",
                            method="GET",
                            endpoint=endpoint or "/",
                            title=f"Potential XSS on {endpoint or '/'}",
                            target_url=target_url,
                            evidence_refs=evidence_refs,
                            success_condition="Confirm reflection or browser-side execution of the injected XSS payload.",
                            verifier_hint="probe_xss",
                        )
                    )
            if any(marker in text_blob for marker in ("sql injection", "sqlite", "syntax error", "database error", "query failed")):
                key = ("sqli", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="sqli",
                            method="GET",
                            endpoint=endpoint or "/",
                            title=f"Potential SQL injection on {endpoint or '/'}",
                            target_url=target_url,
                            evidence_refs=evidence_refs,
                            success_condition="Confirm SQL parser breakage or injection-driven behavior with a bounded probe.",
                            verifier_hint="probe_sqli",
                        )
                    )
            if any(marker in text_blob for marker in ("ssrf", "localhost", "127.0.0.1", "metadata", "server-side request forgery")):
                key = ("ssrf", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="ssrf",
                            method="POST",
                            endpoint=endpoint or "/",
                            title=f"Potential SSRF on {endpoint or '/'}",
                            target_url=target_url,
                            evidence_refs=evidence_refs,
                            success_condition="Confirm whether the server fetches an attacker-controlled internal URL.",
                            verifier_hint="probe_ssrf",
                        )
                    )
            if any(marker in text_blob for marker in ("xxe", "yaml", "upload", "multipart", "doctype", "entity")):
                key = ("upload_bug", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="upload_bug",
                            method="POST",
                            endpoint=endpoint or "/",
                            title=f"Potential upload/parser bug on {endpoint or '/'}",
                            target_url=target_url,
                            evidence_refs=evidence_refs,
                            success_condition="Confirm unsafe file parsing or upload handling with a bounded parser payload.",
                            verifier_hint="probe_upload_bug",
                        )
                    )
            if any(marker in text_blob for marker in ("business logic", "workflow", "checkout", "payment bypass", "membership", "coupon")):
                key = ("business_logic", endpoint)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        _candidate(
                            claim_type="business_logic",
                            method="POST",
                            endpoint=endpoint or "/",
                            title=f"Potential business-logic flaw on {endpoint or '/'}",
                            target_url=target_url,
                            evidence_refs=evidence_refs,
                            success_condition="Confirm the workflow succeeds without the expected ownership, payment, or sequence checks.",
                            verifier_hint="probe_business_logic",
                        )
                    )

    return candidates

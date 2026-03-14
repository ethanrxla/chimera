from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from chimera_core.findings import Finding
from chimera_core.validators.http import response_artifact, similarity_score
from chimera_core.validators.types import ValidationResult


class AuthComparatorValidator:
    async def validate(
        self,
        finding: Finding,
        target_endpoint: str,
        authenticated_creds: Dict[str, Any],
        unauthenticated_headers: Optional[Dict[str, str]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ValidationResult:
        close_client = client is None
        http_client = client or httpx.AsyncClient()
        try:
            auth_response = await http_client.get(target_endpoint, headers=_auth_headers(authenticated_creds))
            anon_response = await http_client.get(target_endpoint, headers=unauthenticated_headers or {})
        finally:
            if close_client:
                await http_client.aclose()

        similarity = similarity_score(auth_response.text, anon_response.text)
        if auth_response.status_code == 200 and anon_response.status_code == 200 and similarity >= 0.9:
            status = "confirmed"
            confidence = 0.9
            explanation = "Authenticated and unauthenticated responses expose the same material content."
        elif anon_response.status_code in {401, 403}:
            status = "false_positive"
            confidence = 0.88
            explanation = "Anonymous access is blocked by the target."
        else:
            status = "inconclusive"
            confidence = 0.6
            explanation = "Access delta exists, but the exposure needs manual review."

        finding.validation_status = "confirmed" if status == "confirmed" else "false_positive" if status == "false_positive" else "needs_replay"
        finding.validation_reason = explanation
        finding.confidence = confidence
        finding.proof_artifacts.extend(
            [
                response_artifact("request", auth_response),
                response_artifact("response", anon_response),
            ]
        )
        finding.replay_steps = [
            {
                "action": "authenticated_request",
                "request": {"endpoint": target_endpoint, "credentials": authenticated_creds},
                "expected_diff": "Baseline authenticated response.",
            },
            {
                "action": "unauthenticated_request",
                "request": {"endpoint": target_endpoint, "headers": unauthenticated_headers or {}},
                "expected_diff": "Anonymous request should return less data or be rejected.",
            },
        ]
        return ValidationResult(
            status=status,
            confidence=confidence,
            proof_artifacts=list(finding.proof_artifacts),
            replay_steps=list(finding.replay_steps),
            explanation=explanation,
        )


def _auth_headers(creds: Dict[str, Any]) -> Dict[str, str]:
    token = creds.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {k: str(v) for k, v in creds.get("headers", {}).items()}

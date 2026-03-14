from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from chimera_core.findings import Finding
from chimera_core.validators.http import response_artifact, similarity_score
from chimera_core.validators.types import ValidationResult


class BOLAValidator:
    async def validate(
        self,
        finding: Finding,
        target_endpoint: str,
        user_a_creds: Dict[str, Any],
        user_b_creds: Dict[str, Any],
        object_id: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ValidationResult:
        close_client = client is None
        http_client = client or httpx.AsyncClient()
        try:
            owner_response = await http_client.get(
                target_endpoint.format(object_id=object_id),
                headers=_auth_headers(user_a_creds),
            )
            peer_response = await http_client.get(
                target_endpoint.format(object_id=object_id),
                headers=_auth_headers(user_b_creds),
            )
        finally:
            if close_client:
                await http_client.aclose()

        similarity = similarity_score(owner_response.text, peer_response.text)
        status = "inconclusive"
        confidence = 0.5
        explanation = "Validator could not classify the authorization result deterministically."
        if owner_response.status_code == 200 and peer_response.status_code == 200 and similarity >= 0.95:
            status = "confirmed"
            confidence = 0.95
            explanation = "Cross-user replay returned materially identical responses."
        elif peer_response.status_code in {403, 404}:
            status = "false_positive"
            confidence = 0.9
            explanation = "Cross-user replay was blocked, which rejects the original BOLA claim."
        elif owner_response.status_code == 200 and peer_response.status_code == 200:
            status = "inconclusive"
            confidence = 0.65
            explanation = "Cross-user replay succeeded but response bodies diverged."

        finding.validation_status = "confirmed" if status == "confirmed" else "false_positive" if status == "false_positive" else "needs_replay"
        finding.validation_reason = explanation
        finding.confidence = confidence
        finding.proof_artifacts.extend(
            [
                response_artifact("request", owner_response),
                response_artifact("response", peer_response),
            ]
        )
        finding.replay_steps = [
            {
                "action": "request_as_owner",
                "request": {"endpoint": target_endpoint, "object_id": object_id, "credentials": user_a_creds},
                "expected_diff": "Owner request should return the canonical object.",
            },
            {
                "action": "request_as_non_owner",
                "request": {"endpoint": target_endpoint, "object_id": object_id, "credentials": user_b_creds},
                "expected_diff": "Non-owner request should be denied or materially different.",
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

from __future__ import annotations

from typing import Optional

import httpx

from chimera_core.findings import Finding
from chimera_core.validators.http import response_artifact
from chimera_core.validators.types import ValidationResult


class RateLimitValidator:
    async def validate(
        self,
        finding: Finding,
        target_endpoint: str,
        burst_count: int = 5,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ValidationResult:
        close_client = client is None
        http_client = client or httpx.AsyncClient()
        responses = []
        try:
            for _ in range(burst_count):
                responses.append(await http_client.get(target_endpoint))
        finally:
            if close_client:
                await http_client.aclose()

        status_codes = [response.status_code for response in responses]
        saw_limit = any(code == 429 for code in status_codes)
        all_allowed = all(code < 400 for code in status_codes)
        if all_allowed and burst_count > 1:
            status = "confirmed"
            confidence = 0.85
            explanation = "Burst traffic completed without rate-limit enforcement."
        elif saw_limit:
            status = "false_positive"
            confidence = 0.9
            explanation = "The target enforced a rate limit during replay."
        else:
            status = "inconclusive"
            confidence = 0.55
            explanation = "The response pattern was mixed and needs manual inspection."

        finding.validation_status = "confirmed" if status == "confirmed" else "false_positive" if status == "false_positive" else "needs_replay"
        finding.validation_reason = explanation
        finding.confidence = confidence
        finding.proof_artifacts.extend([response_artifact("response", response) for response in responses])
        finding.replay_steps = [
            {
                "action": "burst_requests",
                "request": {"endpoint": target_endpoint, "count": burst_count},
                "expected_diff": "At least one replay should be throttled if rate limiting exists.",
            }
        ]
        return ValidationResult(
            status=status,
            confidence=confidence,
            proof_artifacts=list(finding.proof_artifacts),
            replay_steps=list(finding.replay_steps),
            explanation=explanation,
        )

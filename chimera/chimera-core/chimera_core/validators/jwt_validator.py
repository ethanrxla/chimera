from __future__ import annotations

from typing import Iterable

from chimera_core.findings import Finding
from chimera_core.validators.types import ValidationResult


class JWTValidator:
    def validate(
        self,
        finding: Finding,
        token: str,
        allowed_algs: Iterable[str] = ("HS256", "RS256"),
    ) -> ValidationResult:
        parts = token.split(".")
        if len(parts) != 3:
            status = "inconclusive"
            confidence = 0.4
            explanation = "Token is not a well-formed JWT."
        elif '"alg":"none"' in token.replace(" ", "").lower() and "none" not in [alg.lower() for alg in allowed_algs]:
            status = "confirmed"
            confidence = 0.95
            explanation = "The token advertises alg:none outside the allowed policy."
        else:
            status = "false_positive"
            confidence = 0.8
            explanation = "No deterministic JWT misconfiguration matched the provided policy."

        finding.validation_status = "confirmed" if status == "confirmed" else "false_positive" if status == "false_positive" else "needs_replay"
        finding.validation_reason = explanation
        finding.confidence = confidence
        finding.replay_steps = [
            {
                "action": "inspect_jwt_header",
                "request": {"token": token},
                "expected_diff": "Header algorithm should match the accepted signing policy.",
            }
        ]
        return ValidationResult(
            status=status,
            confidence=confidence,
            proof_artifacts=[],
            replay_steps=list(finding.replay_steps),
            explanation=explanation,
        )

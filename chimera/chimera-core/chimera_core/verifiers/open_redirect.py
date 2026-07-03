from __future__ import annotations

from chimera_core.hexstrike.schemas import HttpResponseSummary
from chimera_core.verifiers.base import BaseVerifier, VerificationResult


class OpenRedirectVerifier(BaseVerifier):
    claim_type = "open_redirect"

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        check = plan.checks[0]
        expected_statuses = set(check.success_condition.rules.get("expected_redirect_statuses", []))
        expected_location = check.success_condition.rules.get("location_equals")
        summary = hexstrike_result.summary
        if isinstance(summary, dict):
            status_code = int(summary.get("status_code", 0))
            headers = {str(k): str(v) for k, v in (summary.get("headers") or {}).items()}
        elif isinstance(summary, HttpResponseSummary):
            status_code = summary.status_code
            headers = summary.headers
        else:
            status_code = 0
            headers = {}

        location = headers.get("Location") or headers.get("location") or ""
        if status_code in expected_statuses and expected_location and location == expected_location:
            return VerificationResult(
                verification_id=plan.verification_id,
                check_id=check.check_id,
                claim_type=self.claim_type,
                outcome="passed",
                rationale="Redirect status and Location header matched expected external target.",
                evidence_refs=[
                    hexstrike_result.request_artifact_ref,
                    hexstrike_result.response_artifact_ref,
                    hexstrike_result.normalized_artifact_ref,
                ],
                extracted_targets=list(hexstrike_result.observed_targets),
            )
        return VerificationResult(
            verification_id=plan.verification_id,
            check_id=check.check_id,
            claim_type=self.claim_type,
            outcome="failed",
            rationale="Redirect proof condition not satisfied.",
        )

from __future__ import annotations

from chimera_core.hexstrike.schemas import HttpResponseSummary
from chimera_core.verifiers.base import BaseVerifier, VerificationResult


class ApiSurfaceExposureVerifier(BaseVerifier):
    claim_type = "api_surface_exposure"

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        check = plan.checks[0]
        rules = check.success_condition.rules
        expected_statuses = set(rules.get("status_in", []))
        required_markers = [str(item).lower() for item in rules.get("body_contains_any", [])]
        endpoint_markers = [str(item).lower() for item in rules.get("endpoint_contains_any", [])]
        allow_endpoint_match = bool(rules.get("allow_endpoint_match", False))
        summary = hexstrike_result.summary
        if isinstance(summary, dict):
            status_code = int(summary.get("status_code", 0))
            body_excerpt = str(summary.get("body_excerpt") or "")
        elif isinstance(summary, HttpResponseSummary):
            status_code = summary.status_code
            body_excerpt = summary.body_excerpt
        else:
            status_code = 0
            body_excerpt = ""

        target = str(check.probe_input.url or plan.target or "").lower()
        has_body_marker = any(marker in body_excerpt.lower() for marker in required_markers)
        has_endpoint_marker = any(marker in target for marker in endpoint_markers)
        if status_code in expected_statuses and (has_body_marker or (allow_endpoint_match and has_endpoint_marker)):
            return VerificationResult(
                verification_id=plan.verification_id,
                check_id=check.check_id,
                claim_type=self.claim_type,
                outcome="passed",
                rationale="API surface endpoint returned an expected status and matched the API exposure signature.",
                evidence_refs=[
                    hexstrike_result.request_artifact_ref,
                    hexstrike_result.response_artifact_ref,
                    hexstrike_result.normalized_artifact_ref,
                ],
                extracted_targets=list(hexstrike_result.observed_targets),
                metadata={"status_code": status_code},
            )
        return VerificationResult(
            verification_id=plan.verification_id,
            check_id=check.check_id,
            claim_type=self.claim_type,
            outcome="failed",
            rationale="API surface exposure proof condition not satisfied.",
        )

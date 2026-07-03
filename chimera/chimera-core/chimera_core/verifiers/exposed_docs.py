from __future__ import annotations

from chimera_core.hexstrike.schemas import HttpResponseSummary
from chimera_core.verifiers.base import BaseVerifier, VerificationResult


class ExposedDocsVerifier(BaseVerifier):
    claim_type = "exposed_docs"

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        check = plan.checks[0]
        rules = check.success_condition.rules
        expected_statuses = set(rules.get("status_in", []))
        required_markers = [str(item).lower() for item in rules.get("body_contains_any", [])]
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

        excerpt_lower = body_excerpt.lower()
        has_marker = any(marker in excerpt_lower for marker in required_markers)
        if status_code in expected_statuses and has_marker:
            return VerificationResult(
                verification_id=plan.verification_id,
                check_id=check.check_id,
                claim_type=self.claim_type,
                outcome="passed",
                rationale="Docs endpoint returned expected status and documentation markers.",
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
            rationale="Docs exposure proof condition not satisfied.",
        )

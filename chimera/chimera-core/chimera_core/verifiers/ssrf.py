from __future__ import annotations

from chimera_core.verifiers.base import BaseVerifier, VerificationResult
from chimera_core.verifiers.http_common import default_evidence_refs, extract_summary_fields


class SSRFVerifier(BaseVerifier):
    claim_type = "ssrf"

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        check = plan.checks[0]
        rules = check.success_condition.rules
        expected_statuses = set(rules.get("status_in", [200, 201, 202]))
        markers = [str(item).lower() for item in rules.get("body_contains_any", [])]
        denial_markers = [str(item).lower() for item in rules.get("body_excludes_any", [])]
        status_code, _, body_excerpt = extract_summary_fields(hexstrike_result.summary)
        body_lower = body_excerpt.lower()
        has_positive = any(marker in body_lower for marker in markers if marker)
        blocked = any(marker in body_lower for marker in denial_markers if marker)
        if status_code in expected_statuses and (has_positive or not blocked):
            return VerificationResult(
                verification_id=plan.verification_id,
                check_id=check.check_id,
                claim_type=self.claim_type,
                outcome="passed",
                rationale="Server accepted the outbound target and did not return the configured SSRF block markers.",
                evidence_refs=default_evidence_refs(hexstrike_result),
                extracted_targets=list(hexstrike_result.observed_targets),
                metadata={"status_code": status_code},
            )
        return VerificationResult(
            verification_id=plan.verification_id,
            check_id=check.check_id,
            claim_type=self.claim_type,
            outcome="failed",
            rationale="SSRF proof condition not satisfied.",
        )

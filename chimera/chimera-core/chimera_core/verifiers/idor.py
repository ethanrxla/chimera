from __future__ import annotations

import re

from chimera_core.hexstrike.schemas import HttpResponseSummary
from chimera_core.verifiers.base import BaseVerifier, VerificationResult


class IDORVerifier(BaseVerifier):
    claim_type = "idor"

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        check = plan.checks[0]
        rules = check.success_condition.rules
        expected_statuses = set(rules.get("status_in", []))
        require_numeric_object_id = bool(rules.get("require_numeric_object_id", False))
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

        target = str(check.probe_input.url or plan.target or "")
        has_numeric_object = bool(re.search(r"/\d+(?:$|[/?#])", target))
        body_lower = body_excerpt.lower()
        contains_denial = any(marker in body_lower for marker in ("unauthorized", "forbidden", "access denied"))
        if status_code in expected_statuses and (not require_numeric_object_id or has_numeric_object) and not contains_denial:
            return VerificationResult(
                verification_id=plan.verification_id,
                check_id=check.check_id,
                claim_type=self.claim_type,
                outcome="passed",
                rationale="Alternate object identifier remained accessible with a success status.",
                evidence_refs=[
                    hexstrike_result.request_artifact_ref,
                    hexstrike_result.response_artifact_ref,
                    hexstrike_result.normalized_artifact_ref,
                ],
                extracted_targets=list(hexstrike_result.observed_targets),
                metadata={"status_code": status_code, "probe_target": target},
            )
        return VerificationResult(
            verification_id=plan.verification_id,
            check_id=check.check_id,
            claim_type=self.claim_type,
            outcome="failed",
            rationale="IDOR proof condition not satisfied.",
        )

from __future__ import annotations

from chimera_core.verifiers.admin_exposure import AdminExposureVerifier
from chimera_core.verifiers.api_surface_exposure import ApiSurfaceExposureVerifier
from chimera_core.verifiers.auth_missing import AuthMissingVerifier
from chimera_core.verifiers.business_logic import BusinessLogicVerifier
from chimera_core.verifiers.exposed_docs import ExposedDocsVerifier
from chimera_core.verifiers.idor import IDORVerifier
from chimera_core.verifiers.open_redirect import OpenRedirectVerifier
from chimera_core.verifiers.sqli import SQLiVerifier
from chimera_core.verifiers.ssrf import SSRFVerifier
from chimera_core.verifiers.upload_bug import UploadBugVerifier
from chimera_core.verifiers.xss import XSSVerifier


class VerifierRegistry:
    def __init__(self) -> None:
        xss = XSSVerifier()
        sqli = SQLiVerifier()
        ssrf = SSRFVerifier()
        upload_bug = UploadBugVerifier()
        business_logic = BusinessLogicVerifier()
        self._registry = {
            "admin_exposure": AdminExposureVerifier(),
            "api_surface_exposure": ApiSurfaceExposureVerifier(),
            "auth_missing": AuthMissingVerifier(),
            "idor": IDORVerifier(),
            "open_redirect": OpenRedirectVerifier(),
            "exposed_docs": ExposedDocsVerifier(),
            "xss": xss,
            "reflected_xss": xss,
            "stored_xss": xss,
            "dom_xss": xss,
            "sqli": sqli,
            "sql_injection": sqli,
            "nosql_injection": sqli,
            "ssrf": ssrf,
            "upload_bug": upload_bug,
            "file_upload": upload_bug,
            "xxe": upload_bug,
            "yaml_injection": upload_bug,
            "business_logic": business_logic,
            "payment_bypass": business_logic,
            "workflow_bypass": business_logic,
        }

    def get(self, claim_type: str):
        try:
            return self._registry[claim_type]
        except KeyError as exc:
            raise ValueError(f"No verifier registered for claim_type={claim_type}") from exc

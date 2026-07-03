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
from chimera_core.verifiers.registry import VerifierRegistry
from chimera_core.verifiers.xss import XSSVerifier


def test_verifier_registry_returns_known_verifiers() -> None:
    registry = VerifierRegistry()

    assert isinstance(registry.get("admin_exposure"), AdminExposureVerifier)
    assert isinstance(registry.get("api_surface_exposure"), ApiSurfaceExposureVerifier)
    assert isinstance(registry.get("auth_missing"), AuthMissingVerifier)
    assert isinstance(registry.get("idor"), IDORVerifier)
    assert isinstance(registry.get("open_redirect"), OpenRedirectVerifier)
    assert isinstance(registry.get("exposed_docs"), ExposedDocsVerifier)
    assert isinstance(registry.get("xss"), XSSVerifier)
    assert isinstance(registry.get("dom_xss"), XSSVerifier)
    assert isinstance(registry.get("sqli"), SQLiVerifier)
    assert isinstance(registry.get("ssrf"), SSRFVerifier)
    assert isinstance(registry.get("upload_bug"), UploadBugVerifier)
    assert isinstance(registry.get("business_logic"), BusinessLogicVerifier)

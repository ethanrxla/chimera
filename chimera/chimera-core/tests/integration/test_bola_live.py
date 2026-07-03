"""
Live BOLA / auth validator tests against OWASP Juice Shop.

D1 — BOLAValidator confirms IDOR on /api/Users/1 (two-user cross-access)
D2 — AuthComparatorValidator flags unprotected basket endpoint

Both tests are marked `live` and skip if Juice Shop is unreachable.
"""
import socket
import uuid

import httpx
import pytest

from chimera_core.findings import Finding
from chimera_core.validators.bola_validator import BOLAValidator
from chimera_core.validators.auth_validator import AuthComparatorValidator


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def _can_reach(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_JUICE_SHOP = "http://juice-shop:3000"
_juice_shop_reachable = _can_reach("juice-shop", 3000)

skip_no_juice_shop = pytest.mark.skipif(
    not _juice_shop_reachable,
    reason="juice-shop:3000 not reachable — start with COMPOSE_PROFILES=lab",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _register_and_login(base: str, suffix: str) -> str:
    """Register a new Juice Shop user and return their auth token."""
    email = f"chimera-test-{suffix}-{uuid.uuid4().hex[:8]}@test.local"
    password = "Chimera1!"

    reg_resp = httpx.post(
        f"{base}/api/Users/",
        json={
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?", "createdAt": "2024-01-01T00:00:00.000Z", "updatedAt": "2024-01-01T00:00:00.000Z"},
            "securityAnswer": "test",
        },
        timeout=10,
    )
    assert reg_resp.status_code in {200, 201}, f"Registration failed ({suffix}): {reg_resp.status_code} {reg_resp.text}"

    login_resp = httpx.post(
        f"{base}/rest/user/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    assert login_resp.status_code == 200, f"Login failed ({suffix}): {login_resp.status_code} {login_resp.text}"
    token = login_resp.json()["authentication"]["token"]
    return token


def _stub_finding(target: str) -> Finding:
    return Finding(
        finding_id=f"test:idor:{target}",
        severity="high",
        title="IDOR on user profile endpoint",
        description="Any authenticated user can access any user profile.",
        affected_target=target,
        tool_source="test",
        tool_version="1.0",
        run_id="run-bola-live",
        scope_hash="scope-live",
        finding_type="IDOR",
    )


# ---------------------------------------------------------------------------
# D1 — BOLAValidator confirms IDOR on /api/Users/1
# ---------------------------------------------------------------------------

@pytest.mark.live
@skip_no_juice_shop
@pytest.mark.anyio
async def test_bola_validator_confirms_idor_on_juice_shop():
    """
    Register two Juice Shop users; cross-access /api/Users/1 with user_b's token.
    BOLAValidator must return status='confirmed' with 2 proof artifacts.
    """
    token_a = _register_and_login(_JUICE_SHOP, "user-a")
    token_b = _register_and_login(_JUICE_SHOP, "user-b")

    finding = _stub_finding(f"{_JUICE_SHOP}/api/Users/{{object_id}}")
    validator = BOLAValidator()

    result = await validator.validate(
        finding=finding,
        target_endpoint=f"{_JUICE_SHOP}/api/Users/{{object_id}}",
        user_a_creds={"token": token_a},
        user_b_creds={"token": token_b},
        object_id="1",
    )

    assert result.status == "confirmed", (
        f"Expected BOLA confirmed, got {result.status!r}: {result.explanation}"
    )
    assert result.confidence >= 0.9, f"Confidence too low: {result.confidence}"
    assert len(result.proof_artifacts) >= 2, (
        f"Expected 2 proof artifacts (owner + peer), got {len(result.proof_artifacts)}"
    )
    assert len(result.replay_steps) == 2, (
        f"Expected 2 replay steps, got {len(result.replay_steps)}"
    )


# ---------------------------------------------------------------------------
# D2 — AuthComparatorValidator flags unprotected basket
# ---------------------------------------------------------------------------

@pytest.mark.live
@skip_no_juice_shop
@pytest.mark.anyio
async def test_auth_comparator_flags_unprotected_feedback():
    """
    GET /api/Feedbacks/ is publicly accessible without authentication (Juice Shop).
    AuthComparatorValidator must return 'confirmed' — both auth and anon get identical data.
    """
    token_a = _register_and_login(_JUICE_SHOP, "feedback-tester")

    finding = _stub_finding(f"{_JUICE_SHOP}/api/Feedbacks/")
    validator = AuthComparatorValidator()

    result = await validator.validate(
        finding=finding,
        target_endpoint=f"{_JUICE_SHOP}/api/Feedbacks/",
        authenticated_creds={"token": token_a},
        unauthenticated_headers={},
    )

    # /api/Feedbacks/ returns 200 with the same data regardless of auth token
    assert result.status == "confirmed", (
        f"Expected confirmed (public endpoint exposed regardless of auth), got {result.status!r}: {result.explanation}"
    )
    assert len(result.proof_artifacts) >= 2, (
        f"Expected at least 2 proof artifacts, got {len(result.proof_artifacts)}"
    )

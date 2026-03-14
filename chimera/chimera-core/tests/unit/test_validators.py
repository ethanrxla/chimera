import base64
import json

import httpx
import pytest

from chimera_core.findings import Finding
from chimera_core.validators.auth_validator import AuthComparatorValidator
from chimera_core.validators.bola_validator import BOLAValidator
from chimera_core.validators.jwt_validator import JWTValidator
from chimera_core.validators.rate_limit_validator import RateLimitValidator


def make_finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        severity="medium",
        title="Candidate finding",
        description="desc",
        affected_target="https://example.com/api/users/{object_id}",
        tool_source="unit",
        tool_version="1.0",
        run_id="run-1",
        scope_hash="scope-1",
        finding_type="BOLA",
        asset={"endpoint": "/api/users/{id}", "method": "GET"},
    )


@pytest.mark.asyncio
async def test_bola_validator_confirms_cross_user_access() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "7", "email": "user@example.com"}, request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await BOLAValidator().validate(
            make_finding(),
            "https://example.com/api/users/{object_id}",
            {"token": "owner"},
            {"token": "other"},
            "7",
            client=client,
        )

    assert result.status == "confirmed"
    assert result.confidence >= 0.95
    assert len(result.proof_artifacts) == 2


@pytest.mark.asyncio
async def test_auth_validator_rejects_when_anon_blocked() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization"):
            return httpx.Response(200, text='{"secrets": true}', request=request)
        return httpx.Response(403, text="forbidden", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await AuthComparatorValidator().validate(
            make_finding(),
            "https://example.com/api/admin",
            {"token": "admin"},
            client=client,
        )

    assert result.status == "false_positive"
    assert result.confidence >= 0.88


@pytest.mark.asyncio
async def test_rate_limit_validator_confirms_missing_throttle() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await RateLimitValidator().validate(
            make_finding(),
            "https://example.com/login",
            burst_count=4,
            client=client,
        )

    assert result.status == "confirmed"
    assert len(result.proof_artifacts) == 4


def test_jwt_validator_flags_alg_none() -> None:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}."

    result = JWTValidator().validate(make_finding(), token=token, allowed_algs=("HS256",))

    assert result.status == "confirmed"
    assert result.confidence >= 0.95

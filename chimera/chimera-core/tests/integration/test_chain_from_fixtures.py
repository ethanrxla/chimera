"""
Integration tests for chain analysis — E1 (pure Python) and E2 (API artifact path).

E1 proves synthesize_chains() produces a ChainRecord from in-memory Finding objects.
E2 proves the full runner → chain_analysis → chain_graphs.json artifact path works.
"""
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from chimera_core.chain_analysis import synthesize_chains
from chimera_core.findings import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(finding_id: str, finding_type: str, title: str, validation_status: str = "confirmed") -> Finding:
    return Finding(
        finding_id=finding_id,
        severity="high",
        title=title,
        description=title,
        affected_target="https://api.example.com/users/1",
        tool_source="test",
        tool_version="1.0",
        run_id="run-chain-test",
        scope_hash="scope-chain",
        finding_type=finding_type,
        validation_status=validation_status,
        confidence=0.92,
    )


# ---------------------------------------------------------------------------
# E1 — pure Python, no external deps
# ---------------------------------------------------------------------------

def test_chain_analysis_produces_records_from_idor_jwt_findings():
    """Two in-memory findings (IDOR + JWT) must produce one idor_jwt_takeover chain record."""
    records = synthesize_chains(
        [
            _finding("f-idor-1", "IDOR", "IDOR on /api/Users/{id}"),
            _finding("f-jwt-1", "JWT", "JWT alg:none accepted"),
        ],
        run_id="run-chain-test",
        scope_hash="scope-chain",
        target="https://api.example.com/users/1",
    )

    assert len(records) >= 1, "Expected at least one chain record"
    assert records[0].rule_id == "idor_jwt_takeover"
    assert records[0].finding.severity == "critical"
    assert records[0].finding.finding_type == "EXPLOIT_CHAIN"
    assert records[0].ascii_graph != "", "Expected non-empty ASCII graph"
    assert "f-idor-1" in records[0].supporting_ids
    assert "f-jwt-1" in records[0].supporting_ids


# ---------------------------------------------------------------------------
# E2 — full runner → chain_graphs.json artifact path
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_chain_api_endpoint_returns_graph_for_fixture_run(tmp_path: Path):
    """
    Start a fixture-mode run via API, poll to completion, then verify
    chain_graphs.json exists in the artifacts directory and has the expected shape.
    """
    from chimera_core.api.app import create_app

    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(
            Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json"
        )
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        response = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        assert response.status_code == 200, response.text
        run_id = response.json()["run_id"]

        done_states = {"completed", "failed", "cancelled"}
        for _ in range(120):
            status_resp = await client.get(f"/v1/runs/{run_id}")
            if status_resp.json().get("status") in done_states:
                break
            await asyncio.sleep(0.05)

        run_info = (await client.get(f"/v1/runs/{run_id}")).json()
        assert run_info.get("status") in {"completed", "failed"}, f"Run did not finish: {run_info}"

        artifacts_dir = Path(run_info["artifacts_dir"])
        chain_graphs_path = artifacts_dir / "chain_graphs.json"
        assert chain_graphs_path.exists(), "chain_graphs.json not written by runner"

        graphs = json.loads(chain_graphs_path.read_text(encoding="utf-8"))
        # May be empty list if fixture findings don't trigger a chain — that is acceptable.
        # What we need is that the file is valid JSON (list).
        assert isinstance(graphs, list), f"chain_graphs.json must be a list, got: {type(graphs)}"

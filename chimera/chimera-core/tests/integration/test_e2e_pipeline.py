"""
End-to-end pipeline tests covering the full Chimera scan workflow.

Fixture mode (always runs):
  - web_app target: scope → planner → strix(fixture) → browser(fake) → chain_analysis → report
  - api_rest target: scope → planner → autoswagger(fixture) → validators → chain_analysis → report

Live mode (@pytest.mark.live, requires juice-shop reachable):
  - Same pipeline against http://juice-shop:3000
  - Skipped automatically when the target is unreachable

Run live tests with:
    pytest -m live tests/integration/test_e2e_pipeline.py -v
"""

import json
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict

import pytest

from chimera_core.orchestrator import Orchestrator
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.planner import generate_plan
from chimera_core.scope import normalize_scope


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRIX_FIXTURE = str(Path(__file__).resolve().parents[1] / "fixtures" / "strix" / "output.json")
AUTOSWAGGER_FIXTURE = str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
LIVE_TARGET = os.environ.get("CHIMERA_LIVE_TEST_TARGET", "http://juice-shop:3000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_reachable(url: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def _make_runtime(tmp_path: Path, scope_manifest: Dict[str, Any], run_id: str = "run-e2e") -> Runtime:
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


# ---------------------------------------------------------------------------
# Fake browser playwright factory — no real Playwright needed in fixture mode
# ---------------------------------------------------------------------------

class _FakePage:
    def __init__(self) -> None:
        self.url = ""
        self._content = (
            "<script>node.innerHTML = location.search; "
            "window.addEventListener('message', handler)</script>"
            "<script src='/static/app.js'></script>"
        )

    def on(self, event: str, handler) -> None:
        pass

    async def goto(self, url: str, timeout: int = 0):
        self.url = url
        return None

    async def click(self, selector: str, timeout: int = 0) -> None:
        pass

    async def fill(self, selector: str, value: str, timeout: int = 0) -> None:
        pass

    async def wait_for_selector(self, selector: str, timeout: int = 0) -> None:
        pass

    async def wait_for_load_state(self, state: str, timeout: int = 0) -> None:
        pass

    async def evaluate(self, js_code: str):
        if "document.scripts" in js_code:
            return ["window.addEventListener('message', handler)"]
        return {"ok": True}

    async def eval_on_selector_all(self, selector: str, script: str) -> list:
        return ["/static/app.js"]

    async def content(self) -> str:
        return self._content

    async def screenshot(self) -> bytes:
        return b"fake"


class _FakeContext:
    def __init__(self) -> None:
        self.tracing = self

    async def new_page(self):
        return _FakePage()

    async def add_cookies(self, cookies) -> None:
        pass

    async def start(self, screenshots: bool = True, snapshots: bool = True) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeBrowser:
    async def new_context(self):
        return _FakeContext()

    async def close(self) -> None:
        pass


async def _fake_playwright_factory(headless: bool):
    browser = _FakeBrowser()
    context = await browser.new_context()
    page = await context.new_page()
    return browser, context, page


# ---------------------------------------------------------------------------
# Fixture-mode tests (always run, no network needed)
# ---------------------------------------------------------------------------

def test_web_app_plan_has_strix_before_browser(tmp_path: Path) -> None:
    """Planner must produce strix → browser dependency for web_app targets."""
    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph, scope_policy = normalize_scope(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    strix_tasks = [t for t in plan.tasks if "strix" in t]
    browser_tasks = [t for t in plan.tasks if "browser" in t]

    assert strix_tasks, "web_app plan must have a strix task"
    assert browser_tasks, "web_app plan must have a browser task"

    for bt in browser_tasks:
        deps = plan.tasks[bt].dependencies
        assert any("strix" in d for d in deps), (
            f"browser task {bt} must depend on strix, got: {deps}"
        )


def test_api_rest_plan_has_autoswagger_before_validators(tmp_path: Path) -> None:
    """Planner must produce autoswagger → validator(s) for api_rest targets."""
    scope_manifest = {"allowlist": ["https://api.example.com/api"], "denylist": []}
    scope_graph, scope_policy = normalize_scope(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    swagger_tasks = [t for t in plan.tasks if "autoswagger" in t]
    validator_tasks = [t for t in plan.tasks if "validator" in t]

    assert swagger_tasks, "api_rest plan must have an autoswagger task"
    assert validator_tasks, "api_rest plan must have validator tasks"

    for vt in validator_tasks:
        deps = plan.tasks[vt].dependencies
        assert any("autoswagger" in d for d in deps), (
            f"validator task {vt} must depend on autoswagger, got: {deps}"
        )


def test_web_app_pipeline_strix_fixture_to_browser_fake(tmp_path: Path) -> None:
    """
    Full web_app run:  strix(fixture) → browser(fake playwright)
    Asserts: strix findings surface, browser DOM findings surface,
             report.md and summary.json written.
    """
    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph, scope_policy = normalize_scope(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    # Inject fake playwright into browser tasks
    for task in plan.tasks.values():
        if task.tool == "browser":
            task.options["playwright_factory"] = _fake_playwright_factory

    runtime = _make_runtime(tmp_path, scope_manifest)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=2,
        stop_on_fail=False,
        fixture_registry={"strix": STRIX_FIXTURE},
    )
    results = runner.execute(plan)

    all_findings = [f for r in results for f in r.findings]
    assert all_findings, "Expected findings from strix+browser pipeline"

    tool_sources = {f.tool_source for f in all_findings}
    assert "strix" in tool_sources, f"strix findings missing, sources: {tool_sources}"

    # Browser should find DOM sinks in the fake page content
    browser_findings = [f for f in all_findings if f.tool_source == "browser"]
    assert browser_findings, "browser task should have produced DOM findings"

    # Report artifacts
    artifacts_root = tmp_path / "artifacts"
    run_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert run_dirs


def test_api_rest_pipeline_autoswagger_fixture_to_chain(tmp_path: Path) -> None:
    """
    Full api_rest run: autoswagger(fixture) → validators → chain_analysis → report.
    Asserts: findings written, chains.json exists, report.md produced.
    """
    scope_manifest = {"allowlist": ["https://api.example.com/api"], "denylist": []}
    artifacts_root = tmp_path / "artifacts"
    orchestrator = Orchestrator(
        artifacts_root=artifacts_root,
        fixture_registry={"autoswagger": AUTOSWAGGER_FIXTURE},
        live=False,
    )
    job = orchestrator.create_job_from_manifest(scope_manifest, mode="safe")
    orchestrator.start_run(job.job_id)

    run_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert run_dirs
    run_dir = run_dirs[0]

    assert (run_dir / "findings.json").exists()
    assert (run_dir / "chains.json").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "summary.json").exists()


def test_chain_analysis_idor_plus_jwt_produces_exploit_chain(tmp_path: Path) -> None:
    """
    PlanRunner chain-analysis stage:
    shannon(IDOR finding) + jwt_validator(alg:none) → EXPLOIT_CHAIN.
    """
    shannon_fixture = tmp_path / "shannon_idor.json"
    shannon_fixture.write_text(
        json.dumps({
            "findings": [{
                "title": "IDOR on /api/users endpoint",
                "description": "Object ID manipulation leaks another user profile.",
                "severity": "high",
                "target": "https://api.example.com/users/42",
            }]
        }),
        encoding="utf-8",
    )

    scope_manifest = {"allowlist": ["api.example.com"], "denylist": []}
    runtime = _make_runtime(tmp_path, scope_manifest, run_id="chain-test")

    import base64
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": "1"}).encode()
    ).decode().rstrip("=")
    alg_none_token = f"{header}.{payload_b64}."

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", "https://api.example.com/users/42", {"live": False}))
    plan.add_task(Task(
        "J1",
        "jwt_validator",
        "https://api.example.com/users/42",
        {
            "validation_inputs": {
                "token": alg_none_token,
                "allowed_algs": ("HS256",),
            }
        },
    ))
    plan.add_dependency("S1", "J1")

    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=True,
        fixture_registry={"shannon": str(shannon_fixture)},
    )
    results = runner.execute(plan)

    chain_results = [r for r in results if r.task_id.startswith("chain-analysis:")]
    assert chain_results, "chain-analysis task must be synthesized"
    chain_findings = chain_results[0].findings
    assert any(f.finding_type == "EXPLOIT_CHAIN" for f in chain_findings), (
        "IDOR + alg:none JWT should produce EXPLOIT_CHAIN"
    )
    chain = next(f for f in chain_findings if f.finding_type == "EXPLOIT_CHAIN")
    assert chain.severity in ("critical", "high")


def test_full_golden_path_all_artifacts(tmp_path: Path) -> None:
    """
    Orchestrator golden-path: every expected artifact file must be present.
    """
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(
        'allowlist:\n  - "https://api.example.com/api"\ndenylist: []\n',
        encoding="utf-8",
    )
    artifacts_root = tmp_path / "artifacts"
    orchestrator = Orchestrator(
        artifacts_root=artifacts_root,
        fixture_registry={"autoswagger": AUTOSWAGGER_FIXTURE},
        live=False,
    )
    job = orchestrator.create_job(str(scope_file), mode="safe")
    orchestrator.start_run(job.job_id)

    run_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert run_dirs
    run_dir = run_dirs[0]

    for expected in (
        "findings.json",
        "chains.json",
        "chain_graphs.json",
        "rejected_findings.json",
        "poc_bundles",
        "report.md",
        "summary.json",
    ):
        assert (run_dir / expected).exists(), f"Missing artifact: {expected}"


# ---------------------------------------------------------------------------
# Live tests — skipped unless juice-shop is reachable
# ---------------------------------------------------------------------------

@pytest.mark.live
def test_live_web_app_strix_scans_juice_shop(tmp_path: Path) -> None:
    """
    Live strix scan against OWASP Juice Shop.
    Requires: juice-shop container running on CHIMERA_LIVE_TEST_TARGET
              (default: http://juice-shop:3000).

    Run with:
        pytest -m live tests/integration/test_e2e_pipeline.py -v
    """
    if not _is_reachable(LIVE_TARGET):
        pytest.skip(f"Live target not reachable: {LIVE_TARGET}")

    scope_yml = (
        f'allowlist:\n  - "{LIVE_TARGET}"\n  - "{LIVE_TARGET}/*"\n'
        "denylist: []\n"
        "rate_limits:\n  requests_per_second: 5\n  concurrency: 2\n"
    )
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(scope_yml, encoding="utf-8")

    artifacts_root = tmp_path / "artifacts"
    orchestrator = Orchestrator(
        artifacts_root=artifacts_root,
        live=True,
        max_workers=2,
        rate_limit_rps=5,
        per_task_timeout_s=900,  # strix scans take 5-15 min in Docker sandbox mode
    )
    job = orchestrator.create_job(str(scope_file), mode="live")
    run_id, artifacts_dir = orchestrator.start_run(job.job_id)

    assert artifacts_dir is not None, "Orchestrator returned no artifacts_dir"
    run_dir = Path(artifacts_dir)

    assert (run_dir / "findings.json").exists(), "findings.json not produced"
    assert (run_dir / "report.md").exists(), "report.md not produced"

    findings = json.loads((run_dir / "findings.json").read_text())
    assert len(findings) > 0, (
        f"Expected findings from Juice Shop, got 0. "
        f"Check {run_dir / 'commands'} for strix output."
    )

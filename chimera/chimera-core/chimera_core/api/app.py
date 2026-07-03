import os
from pathlib import Path
from fastapi import FastAPI

from chimera_core.api.routes import router
from chimera_core.api.recon_routes import router as recon_router
from chimera_core.policy.kernel import PolicyKernel
from chimera_core.run_store import RunStore


def create_app(testing: bool = False) -> FastAPI:
    app = FastAPI(title="Chimera API", version="0.1.0")
    app.state.runs = {}
    app.state.testing = testing

    if testing:
        artifacts_root = Path.cwd() / "artifacts"
        fixtures_root = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    else:
        artifacts_root = Path(os.getenv("CHIMERA_ARTIFACTS_DIR", Path.cwd() / "artifacts"))
        fixtures_root = Path(os.getenv("CHIMERA_FIXTURES_DIR", Path(__file__).resolve().parents[2] / "tests" / "fixtures"))
    app.state.artifacts_root = artifacts_root
    app.state.run_store = RunStore(artifacts_root)
    allowed_bins = os.getenv("CHIMERA_ALLOWED_BINARIES", "bash,sh,python,python3,autoswagger,strix,curl")
    app.state.runtime_allowlist = [name.strip() for name in allowed_bins.split(",") if name.strip()]
    app.state.fixture_registry = {
        "autoswagger": str(fixtures_root / "autoswagger" / "output.json"),
        "strix": str(fixtures_root / "strix" / "output.json"),
    }
    app.state.browser_sessions = {}
    app.state.terminal_sessions = {}
    app.state.shannon_tasks = {}
    app.state.browser_playwright_factory = None
    app.state.browser_capture_factory = None
    app.state.browser_llm_callable = None
    app.state.shannon_http_client = None
    app.state.shannon_oracle_callable = None
    app.state.policy_kernel = PolicyKernel.from_path(os.getenv("CHIMERA_POLICY_PATH"))

    app.include_router(router, prefix="/v1")
    app.include_router(recon_router, prefix="/v1")
    app.state.recon_runs = {}  # Store for recon pipeline runs
    return app

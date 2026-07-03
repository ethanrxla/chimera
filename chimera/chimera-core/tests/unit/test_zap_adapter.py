import json
from pathlib import Path

from chimera_core.adapters.zap_adapter import ZapAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    run_id = "run-zap"
    artifacts_root = tmp_path / "artifacts"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=EventStore(run_dir / "events.jsonl"),
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


def make_adapter(tmp_path: Path, options=None, scope_hash: str = "scope-zap") -> ZapAdapter:
    return ZapAdapter(
        runtime=make_runtime(tmp_path),
        options=options,
        run_id="run-zap",
        task_id="TZ1",
        scope_hash=scope_hash,
    )


def sample_raw_output() -> str:
    return json.dumps(
        {
            "target": "https://www.example.com",
            "alerts": [
                {
                    "pluginid": "40012",
                    "name": "Cross Site Scripting (Reflected)",
                    "risk": "High",
                    "confidence": "Medium",
                    "url": "https://www.example.com/search?q=test",
                    "param": "q",
                    "attack": "<svg/onload=alert(1)>",
                    "evidence": "<svg/onload=alert(1)>",
                    "description": "Reflected XSS was detected in the search endpoint.",
                    "solution": "Escape reflected output.",
                    "reference": "https://owasp.org/",
                    "cweid": "79",
                },
                {
                    "pluginid": "10020",
                    "name": "Missing Anti-clickjacking Header",
                    "risk": "Medium",
                    "confidence": "Low",
                    "url": "https://www.example.com/account",
                    "param": "",
                    "attack": "",
                    "evidence": "",
                    "description": "The response did not set X-Frame-Options.",
                    "solution": "Set a framing policy.",
                    "reference": "https://owasp.org/",
                    "cweid": "1021",
                },
            ],
        }
    )


def test_zap_normalizes_alerts_into_findings(tmp_path: Path) -> None:
    adapter = make_adapter(tmp_path)

    findings = adapter.normalize(sample_raw_output())

    assert len(findings) == 2
    assert findings[0].tool_source == "zap"
    assert findings[0].tool_version == "owasp-zap"
    assert findings[0].finding_type == "XSS"
    assert findings[0].asset == {
        "host": "www.example.com",
        "endpoint": "/search",
        "method": "GET",
        "parameter": "q",
    }
    assert findings[0].confidence == 0.72
    assert findings[1].finding_type == "CLICKJACKING"
    assert findings[1].confidence == 0.55


def test_zap_run_writes_raw_output_and_findings_artifacts(tmp_path: Path) -> None:
    raw_output = sample_raw_output()
    adapter = make_adapter(tmp_path, options={"raw_output_override": raw_output})

    result = adapter.run(["https://www.example.com"])

    assert len(result["findings"]) == 2
    raw_artifacts = [artifact for artifact in result["artifacts"] if artifact["artifact_type"] == "raw_output"]
    findings_artifacts = [artifact for artifact in result["artifacts"] if artifact["artifact_type"] == "findings"]
    report_artifacts = [artifact for artifact in result["artifacts"] if artifact["artifact_type"] == "report"]
    assert len(raw_artifacts) == 1
    assert len(findings_artifacts) == 1
    assert len(report_artifacts) == 1
    assert Path(raw_artifacts[0]["path"]).read_text(encoding="utf-8") == raw_output
    assert Path(findings_artifacts[0]["path"]).exists()
    assert "OWASP ZAP Report" in Path(report_artifacts[0]["path"]).read_text(encoding="utf-8")


def test_zap_live_mode_uses_scanner_factory(tmp_path: Path) -> None:
    class _Scanner:
        async def run_scan(self, config):
            assert config.target_url == "https://www.example.com"
            return json.loads(sample_raw_output())

    adapter = make_adapter(
        tmp_path,
        options={
            "live": True,
            "scanner_factory": lambda: _Scanner(),
            "use_ajax_spider": False,
        },
    )

    result = adapter.run(["https://www.example.com"])

    assert len(result["findings"]) == 2

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse
from urllib.parse import urlparse

from chimera_core.adapters.base import AdapterBase
from chimera_core.findings import Finding, stable_finding_id
from chimera_core.runtime import Runtime


_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}

_CONFIDENCE_MAP = {
    "high": 0.88,
    "medium": 0.72,
    "low": 0.55,
}


class ZapAdapter(AdapterBase):
    id = "zap"
    capabilities = ["web-scanning", "passive-analysis"]

    def __init__(
        self,
        runtime: Runtime,
        options: Optional[Dict[str, object]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.scope_policy = runtime.scope_policy
        self.options = options or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root

    def _artifact_dir(self) -> Path:
        return Path(self.artifacts_root) / self.run_id / self.id / self.task_id

    def _artifact_path(self, filename: str) -> Path:
        return self._artifact_dir() / filename

    def _emit_event(self, event_type: str, payload: Dict[str, object]) -> None:
        if not self.runtime or not self.runtime.event_store:
            return
        self.runtime.event_store.emit({"event_type": event_type, "payload": payload})

    def _save_artifact(self, filename: str, content: str) -> str:
        path = self._artifact_path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def validate_targets(self, targets: List[str]) -> None:
        for target in targets:
            if not self.scope_graph.is_in_scope(target):
                raise ValueError(f"Target out of scope: {target}")

    def run(self, targets: List[str]) -> dict:
        if not targets:
            raise ValueError("ZAP adapter requires at least one target")
        self.validate_targets(targets)

        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        raw_output = self._load_raw_output(targets)
        findings = self.normalize(raw_output)
        report_html = self._render_report(findings)

        artifacts = []
        raw_path = self._save_artifact("raw_output.json", raw_output)
        findings_path = self._save_artifact(
            "findings.json",
            json.dumps([finding.to_dict() for finding in findings], indent=2),
        )
        report_path = self._save_artifact("report.html", report_html)

        for path, artifact_type in (
            (raw_path, "raw_output"),
            (findings_path, "findings"),
            (report_path, "report"),
        ):
            artifacts.append({"path": path, "artifact_type": artifact_type, "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": path, "artifact_type": artifact_type, "tool": self.id},
            )

        self._emit_event("cmd_finished", {"run_id": self.run_id, "task_id": self.task_id, "returncode": 0})
        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        return {
            "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": findings,
            "command": None,
        }

    def _load_raw_output(self, targets: List[str]) -> str:
        raw_output_override = self.options.get("raw_output_override")
        fixture_path = self.options.get("fixture_path")
        live = bool(self.options.get("live", False))

        if raw_output_override is not None:
            return str(raw_output_override)
        if fixture_path:
            self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "fixture"})
            return Path(str(fixture_path)).read_text(encoding="utf-8")
        if live:
            self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "live"})
            return self._run_live_scan(targets[0])
        self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "empty"})
        return json.dumps({"target": targets[0], "alerts": []})

    def _run_live_scan(self, target: str) -> str:
        scanner_factory = self.options.get("scanner_factory")
        if callable(scanner_factory):
            scanner = scanner_factory()
            config = self._build_scan_config(target, scan_config_ctor=None)
            result = self._run_async_scan(scanner, config)
            return json.dumps(result)

        base_url = str(self.options.get("base_url") or os.getenv("ZAP_BASE_URL") or "http://127.0.0.1:8080")
        api_key = str(self.options.get("api_key") or os.getenv("ZAP_API_KEY") or "")

        zypheron_root = Path(__file__).resolve().parents[4] / "tools" / "zypheron" / "zypheron-ai"
        if str(zypheron_root) not in sys.path:
            sys.path.insert(0, str(zypheron_root))
        try:
            from integrations.zap.zap_api import ZAPAPI, ZAPConfig
            from integrations.zap.zap_scanner import ZAPScanConfig, ZAPScanner

            parsed = urlparse(base_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 8080
            zap_api = ZAPAPI(ZAPConfig(host=host, port=port, proxy_port=port, api_key=api_key or None))
            scanner = ZAPScanner(zap_api=zap_api)
            result = self._run_async_scan(scanner, self._build_scan_config(target, scan_config_ctor=ZAPScanConfig))
            return json.dumps(result)
        except ImportError:
            return self._run_zap_rest(target, base_url, api_key)

    def _run_zap_rest(self, target: str, base_url: str, api_key: str) -> str:
        """Direct ZAP REST API path — used when Zypheron integration is unavailable."""
        import time
        import urllib.request

        base = base_url.rstrip("/")
        key_param = f"&apikey={api_key}" if api_key else ""
        max_minutes = int(self.options.get("max_duration_minutes", 30))

        def _get(path: str) -> Any:
            url = f"{base}{path}"
            with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
                return json.loads(resp.read())

        # Spider scan
        start = _get(f"/JSON/spider/action/scan/?url={urllib.parse.quote(target, safe='')}{key_param}")
        scan_id = start.get("scan", "0")
        deadline = time.monotonic() + max_minutes * 60
        while time.monotonic() < deadline:
            status = _get(f"/JSON/spider/view/status/?scanId={scan_id}{key_param}")
            if int(status.get("status", 0)) >= 100:
                break
            time.sleep(5)

        # Fetch alerts
        alerts_resp = _get(f"/JSON/core/view/alerts/?baseurl={urllib.parse.quote(target, safe='')}{key_param}")
        alerts = alerts_resp.get("alerts", [])
        return json.dumps({"target": target, "alerts": alerts})

    def _run_async_scan(self, scanner: Any, config: Any) -> Dict[str, Any]:
        import asyncio

        return asyncio.run(scanner.run_scan(config))

    def _build_scan_config(self, target: str, scan_config_ctor: Any) -> Any:
        payload = {
            "target_url": target,
            "scan_type": "both" if self.options.get("active_scan") else "spider",
            "use_ajax_spider": bool(self.options.get("use_ajax_spider", True)),
            "max_depth": int(self.options.get("max_depth", 5)),
            "recurse": bool(self.options.get("recurse", True)),
            "in_scope_only": bool(self.options.get("in_scope_only", True)),
            "exclude_patterns": list(self.options.get("exclude_patterns") or []),
            "max_duration_minutes": int(self.options.get("max_duration_minutes", 30)),
        }
        if scan_config_ctor is None:
            from types import SimpleNamespace

            return SimpleNamespace(**payload)
        return scan_config_ctor(**payload)

    def normalize(self, raw_output: str) -> List[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        alerts = data.get("alerts")
        if not isinstance(alerts, list):
            return []

        findings: List[Finding] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            target = str(alert.get("url") or data.get("target") or "unknown")
            title = str(alert.get("name") or "OWASP ZAP Alert")
            description = self._alert_description(alert)
            severity = _SEVERITY_MAP.get(str(alert.get("risk") or "medium").lower(), "medium")
            signature = str(alert.get("pluginid") or alert.get("id") or "")
            finding_type = self._infer_finding_type(title, alert)
            confidence = _CONFIDENCE_MAP.get(str(alert.get("confidence") or "low").lower(), 0.5)
            evidence_refs = [ref for ref in [alert.get("evidence"), alert.get("reference")] if ref]

            findings.append(
                Finding(
                    finding_id=stable_finding_id(title, target, self.id, signature or None),
                    severity=severity,
                    title=title,
                    description=description,
                    affected_target=target,
                    tool_source=self.id,
                    tool_version="owasp-zap",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    evidence_refs=[str(ref) for ref in evidence_refs],
                    repro_guidance=str(alert.get("attack") or alert.get("solution") or ""),
                    timestamps=datetime.now(timezone.utc),
                    finding_type=finding_type,
                    asset={
                        "host": urlparse(target).hostname or target,
                        "endpoint": urlparse(target).path or "/",
                        "method": "GET",
                        "parameter": str(alert.get("param") or "") or None,
                    },
                    confidence=confidence,
                )
            )
        return findings

    def _alert_description(self, alert: Dict[str, object]) -> str:
        parts = [
            str(alert.get("description") or "").strip(),
            str(alert.get("solution") or "").strip(),
        ]
        return "\n\n".join(part for part in parts if part)

    def _infer_finding_type(self, title: str, alert: Dict[str, object]) -> str:
        lowered = title.lower()
        if "xss" in lowered or "cross site scripting" in lowered:
            return "XSS"
        if "clickjacking" in lowered or str(alert.get("cweid") or "") == "1021":
            return "CLICKJACKING"
        if "sql injection" in lowered:
            return "SQLI"
        if "csrf" in lowered:
            return "CSRF"
        return "WEB_ALERT"

    def _render_report(self, findings: List[Finding]) -> str:
        lines = [
            "<html><body>",
            "<h1>OWASP ZAP Report</h1>",
            f"<p>Target findings: {len(findings)}</p>",
            "<ul>",
        ]
        for finding in findings:
            lines.append(f"<li>{finding.severity.upper()}: {finding.title} ({finding.affected_target})</li>")
        lines.extend(["</ul>", "</body></html>"])
        return "\n".join(lines)

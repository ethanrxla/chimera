import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List

from chimera_core.runtime import Runtime
from chimera_core.modules.recon_gatherers.schemas import ReconBundle
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig # Re-using for generic config shape
from chimera_core.modules.recon_gatherers.enrichment.models import EnrichmentResult, ArtifactRef
from chimera_core.modules.recon_gatherers.parsers.vibepentester_parser import ParseWarning
from chimera_core.modules.runtime.tool_profile import ToolProfile
from chimera_core.tool_runner import ToolRunner

# Define a more generic config for command-line tools
DecepticonConfig = VibePenTesterConfig

class DecepticonExecutionError(Exception):
    pass

@dataclass
class DecepticonAdapter:
    """
    Adapter for running the Decepticon tool as an enrichment stage.
    """
    runtime: Runtime
    TOOL_PROFILE = ToolProfile(name="decepticon", is_destructive=False, default_timeout_s=1800, max_timeout_s=3600)

    def _prepare_input(self, bundles: List[ReconBundle], input_dir: Path) -> Path:
        """Serializes ReconBundles to a JSON file for Decepticon to consume."""
        input_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "bundles": [
                {
                    "run_id": bundle.run_id,
                    "target": bundle.target,
                    "tool": bundle.tool,
                    "observed_assets": [
                        {
                            "type": asset.type,
                            "value": asset.value,
                            "source_tool": asset.source_tool,
                        }
                        for asset in bundle.observed_assets
                    ],
                    "services": [
                        {
                            "host": service.host,
                            "port": service.port,
                            "proto": service.proto,
                            "service": service.service,
                            "banner": service.banner,
                            "confidence": service.confidence,
                        }
                        for service in bundle.services
                    ],
                    "web_endpoints": [
                        {
                            "url": endpoint.url,
                            "method": endpoint.method,
                            "params": endpoint.params,
                            "discovered_by": endpoint.discovered_by,
                        }
                        for endpoint in bundle.web_endpoints
                    ],
                    "findings": [
                        {
                            "title": finding.title,
                            "type": finding.type,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "evidence_refs": finding.evidence_refs,
                            "reproduction": finding.reproduction,
                            "tags": finding.tags,
                            "raw_tool_fields": finding.raw_tool_fields,
                        }
                        for finding in bundle.findings
                    ],
                    "artifacts": [
                        {
                            "path": artifact.path,
                            "kind": artifact.kind,
                            "sha256": artifact.sha256,
                        }
                        for artifact in bundle.artifacts
                    ],
                }
                for bundle in bundles
            ],
        }

        input_path = input_dir / "bundles.json"
        input_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return input_path

    def _collect_output_artifacts(self, output_dir: Path, run_artifacts_dir: Path) -> List[ArtifactRef]:
        collected: List[ArtifactRef] = []
        if not output_dir.is_dir():
            return collected

        output_artifacts_dir = run_artifacts_dir / "outputs"
        output_artifacts_dir.mkdir(parents=True, exist_ok=True)

        for output_file in output_dir.iterdir():
            if not output_file.is_file():
                continue
            destination = output_artifacts_dir / output_file.name
            shutil.copy(output_file, destination)
            content = output_file.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()
            collected.append(
                ArtifactRef(
                    path=str(destination),
                    kind="decepticon_output",
                    sha256=sha256,
                )
            )
        return collected

    def run_enrichment(self, bundles: List[ReconBundle], config: DecepticonConfig) -> EnrichmentResult:
        """
        Executes the Decepticon tool and collects the resulting artifacts.
        This MVP implementation does not yet parse the output.
        """
        run_id = self.runtime.run_id
        run_artifacts_dir = self.runtime.artifacts_root / run_id / "decepticon"
        run_artifacts_dir.mkdir(parents=True, exist_ok=True)

        input_dir = run_artifacts_dir / "input"
        input_path = self._prepare_input(bundles, input_dir)

        config.output_dir.mkdir(parents=True, exist_ok=True)

        tool_runner = ToolRunner(self.runtime)
        base_command = tool_runner.base_command("decepticon", config.entrypoint)
        cmd = base_command + ["--input", str(input_path), "--output", str(config.output_dir)] + config.extra_args

        result = tool_runner.run_external(
            "decepticon",
            cmd,
            cwd=config.workdir,
            env=config.env,
            timeout_s=config.timeout_s,
            tool_profile=self.TOOL_PROFILE,
            mode=config.mode,
        )

        if not result.ok:
            raise DecepticonExecutionError(result.stderr)

        stdout_path = run_artifacts_dir / "stdout.txt"
        stderr_path = run_artifacts_dir / "stderr.txt"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")

        artifacts: List[ArtifactRef] = [
            ArtifactRef(
                path=str(stdout_path),
                kind="stdout",
                sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
            ),
            ArtifactRef(
                path=str(stderr_path),
                kind="stderr",
                sha256=hashlib.sha256(result.stderr.encode()).hexdigest(),
            ),
        ]

        output_artifacts = self._collect_output_artifacts(config.output_dir, run_artifacts_dir)
        artifacts.extend(output_artifacts)

        warnings: List[ParseWarning] = []
        if not output_artifacts:
            warnings.append(
                ParseWarning(
                    artifact_path=str(config.output_dir),
                    reason="Decepticon produced no output artifacts.",
                )
            )

        return EnrichmentResult(
            notes_markdown="",
            suggested_actions=[],
            promoted_findings=[],
            artifacts=artifacts,
            warnings=warnings,
        )

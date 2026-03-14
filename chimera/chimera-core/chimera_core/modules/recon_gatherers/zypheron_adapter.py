import re
import hashlib
import traceback
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

from chimera_core.runtime import Runtime, ExternalToolTimeout, ToolOutputError
from chimera_core.modules.runtime.tool_profile import ToolProfile
from chimera_core.tool_runner import ToolRunner
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, ObservedAsset, Service, Artifact, Finding

@dataclass
class ZypheronAdapter:
    runtime: Runtime

    TOOL_PROFILE = ToolProfile(name="zypheron", is_destructive=False, default_timeout_s=1800, max_timeout_s=3600)

    def _parse_zypheron_output(self, stdout_content: str, stderr_content: str, command: List[str]) -> Tuple[List[ObservedAsset], List[Service], List[Finding]]:
        observed_assets: List[ObservedAsset] = []
        services: List[Service] = []
        findings: List[Finding] = []

        for line in stdout_content.splitlines():
            if "[ASSET] host:" in line:
                match = re.search(r"\[ASSET\] host: (\S+)", line)
                if match: 
                    observed_assets.append(ObservedAsset(type="host", value=match.group(1), source_tool="zypheron"))
            elif "[ASSET] domain:" in line:
                match = re.search(r"\[ASSET\] domain: (\S+)", line)
                if match:
                    observed_assets.append(ObservedAsset(type="domain", value=match.group(1), source_tool="zypheron"))
            elif "[SERVICE]" in line:
                match = re.search(r"\[SERVICE\] host: (\S+), port: (\d+), proto: (\S+), service: (\S+)", line)
                if match:
                    services.append(Service(
                        host=match.group(1),
                        port=int(match.group(2)),
                        proto=match.group(3),
                        service=match.group(4),
                        banner=None,
                        confidence=None,
                    ))
        
        # Simple error finding based on stderr presence for now
        if stderr_content.strip():
             findings.append(Finding(
                title="Zypheron reported errors to stderr",
                type="error",
                severity="low", # Changed to low as this might just be verbose info
                confidence="medium",
                evidence_refs=[], # Will be added later by run_scan if artifact is saved
                reproduction=f"Examine stderr output from Zypheron: {stderr_content.strip()}",
                raw_tool_fields={"stderr": stderr_content}
            ))

        return observed_assets, services, findings

    def run_scan(self, target: str, timeout_s: Optional[int] = None) -> ReconBundle:
        run_id = self.runtime.run_id
        artifacts_dir = self.runtime.artifacts_root / run_id / "zypheron"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        tool_runner = ToolRunner(self.runtime)
        command = tool_runner.base_command("zypheron", ["zypheron"])
        command.extend(["scan", target])
        stdout_path = artifacts_dir / "zypheron_stdout.txt"
        stderr_path = artifacts_dir / "zypheron_stderr.txt"

        try:
            result = tool_runner.run_external(
                "zypheron",
                command,
                timeout_s=timeout_s,
                tool_profile=self.TOOL_PROFILE,
                mode=self.runtime.mode,
            )

            stdout_content = result.stdout or ""
            stderr_content = result.stderr or ""

            stdout_path.write_text(stdout_content, encoding="utf-8")
            stderr_path.write_text(stderr_content, encoding="utf-8")
            
            artifacts = [
                Artifact(
                    path=str(stdout_path),
                    kind="stdout",
                    sha256=hashlib.sha256(stdout_content.encode()).hexdigest(),
                ),
                Artifact(
                    path=str(stderr_path),
                    kind="stderr",
                    sha256=hashlib.sha256(stderr_content.encode()).hexdigest(),
                ),
            ]

            observed_assets, services, findings = self._parse_zypheron_output(stdout_content, stderr_content, command)

            # Create a finding if the tool itself reported an error (non-zero exit code)
            if not result.ok or result.exit_code != 0: 
                # Remove any existing stderr findings if a command execution failure is detected
                findings = [f for f in findings if f.title != "Zypheron reported errors to stderr"]
                findings.append(Finding(
                    title="Zypheron command execution failed",
                    type="error",
                    severity="high",
                    confidence="high",
                    evidence_refs=[str(stderr_path)],
                    reproduction=f"Run command: {' '.join(command)}\nExit Code: {result.exit_code}\nStderr: {stderr_content.strip()}",
                    raw_tool_fields={"stdout": stdout_content, "stderr": stderr_content, "exit_code": result.exit_code}
                ))


            return ReconBundle(
                run_id=run_id,
                target=target,
                tool="zypheron",
                observed_assets=observed_assets,
                services=services,
                artifacts=artifacts,
                findings=findings,
            )
        except ExternalToolTimeout as e:
            raise e
        except Exception as e:
            error_bundle = ReconBundle(
                run_id=run_id,
                target=target,
                tool="zypheron",
                findings=[
                    Finding(
                        title="Zypheron Adapter internal error",
                        type="error",
                        severity="critical",
                        confidence="high",
                        evidence_refs=[],
                        reproduction=f"Internal error during Zypheron scan for {target}: {e}",
                        raw_tool_fields={"error": str(e), "traceback": traceback.format_exc() if 'traceback' in locals() else "N/A"}
                    )
                ],
                artifacts=[
                     Artifact(
                        path=str(stderr_path) if 'stderr_path' in locals() else "",
                        kind="stderr_on_error",
                        sha256=hashlib.sha256(str(e).encode()).hexdigest(),
                    )
                ]
            )
            raise e

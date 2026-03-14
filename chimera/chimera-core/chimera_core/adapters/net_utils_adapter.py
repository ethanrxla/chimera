import subprocess
from pathlib import Path
from typing import List, Optional, Dict
from chimera_core.findings import Finding
from datetime import datetime
import hashlib
from chimera_core.adapters.base import AdapterBase
from chimera_core.scope import ScopeGraph, ScopePolicy # Added imports

# A placeholder for the unified Finding schema
# class Finding:
#     def __init__(self, title, description):
#         self.title = title
#         self.description = description

#     def __repr__(self):
#         return f"Finding(title='{self.title}', description='{self.description}')"

class NetUtilsAdapter(AdapterBase):
    id = "net-utils"
    capabilities = ["recon"]

    def __init__(self, scope_graph: ScopeGraph, scope_policy: ScopePolicy, options: Optional[Dict[str, object]] = None, rate_limits: Optional[Dict[str, int]] = None, run_id: Optional[str] = None, task_id: Optional[str] = None, artifacts_root: Optional[Path] = None):
        self.scope_graph = scope_graph
        self.scope_policy = scope_policy
        self.options = options or {}
        self.rate_limits = rate_limits or {}
        self.script_path = "/home/neo/kali-docker/tools/chimera-net-utils/net-utils.sh"
        self.run_id = run_id or "mock_run_id"
        self.task_id = task_id or "mock_task_id"
        self.artifacts_root = artifacts_root

    def run(self, targets: List[str]) -> dict:
        """
        Executes the net-utils.sh script with the appropriate subcommand
        based on the adapter's options.
        """
        if not targets:
            raise ValueError("No targets provided for NetUtilsAdapter.run")

        # For this mock tool, we'll just run a subdomain scan on the first target provided.
        target = targets[0]
        command = [self.script_path, "subdomain_scan", target]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            raw_output = process.stdout
            artifacts = []
            if self.artifacts_root:
                artifacts_dir = self.artifacts_root / self.id / self.task_id
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                output_path = artifacts_dir / "raw_output.txt"
                output_path.write_text(raw_output, encoding="utf-8")
                artifacts.append({
                    "path": str(output_path),
                    "artifact_type": "raw_output",
                    "tool": self.id,
                })
            return {
                "events": [{"level": "info", "message": f"Completed {self.id} scan for {target}"}],
                "artifacts": artifacts,
                "raw_output_refs": [raw_output]
            }
        except subprocess.CalledProcessError as e:
            error_message = e.stderr
            return {
                "events": [{"level": "error", "message": error_message}],
                "artifacts": [],
                "raw_output_refs": []
            }

    def normalize(self, raw_output: str) -> List[Finding]:
        """
        Normalizes the raw output from the net-utils.sh script into a list
        of Finding objects.
        """
        findings = []

        # A simple normalization rule for subdomain scans
        if "Subdomains found for" in raw_output:
            # Extract subdomains (simple parsing for now)
            subdomains_list = [line.strip() for line in raw_output.splitlines() if line.startswith('mail.') or line.startswith('calendar.') or line.startswith('drive.')]

            for subdomain in subdomains_list:
                title = "Subdomain Discovered"
                description = f"Discovered subdomain: {subdomain}"
                affected_target = subdomain
                tool_source = self.id
                tool_version = "0.1.0" # Placeholder for now
                run_id = self.run_id
                scope_hash = "mock_scope_hash" # Placeholder for now

                # Generate a stable finding_id
                finding_content = f"{title}-{affected_target}-{tool_source}"
                finding_id = hashlib.sha256(finding_content.encode()).hexdigest()

                findings.append(
                    Finding(
                        finding_id=finding_id,
                        severity="info",
                        title=title,
                        description=description,
                        affected_target=affected_target,
                        tool_source=tool_source,
                        tool_version=tool_version,
                        run_id=run_id,
                        scope_hash=scope_hash,
                    )
                )
        return findings

if __name__ == '__main__':
    # Example usage
    mock_scope = {"allowlist": ["invalid.example"]}
    adapter = NetUtilsAdapter(scope=mock_scope, options={}, rate_limits={})
    run_output = adapter.run()
    print("--- Raw Output ---")
    print(run_output["raw_output_refs"][0])
    print("--- Normalized Findings ---")
    findings = adapter.normalize(run_output)
    for finding in findings:
        print(finding.to_dict())

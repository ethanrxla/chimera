import hashlib
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from chimera_core.modules.recon_gatherers.schemas import ReconBundle
from chimera_core.modules.recon_gatherers.enrichment.models import EnrichmentResult, SuggestedAction, ArtifactRef
from chimera_core.modules.recon_gatherers.provenance.models import ProvenanceRef
from chimera_core.modules.recon_gatherers.parsers.vibepentester_parser import ParseWarning
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonAdapter, DecepticonConfig
from chimera_core.modules.recon_gatherers.enrichment.parsers.decepticon_output_parser import parse_decepticon_output
from chimera_core.scope import ScopeGraph

def _confidence_to_float(value: Optional[str]) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except ValueError:
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return mapping.get(value.lower(), 0.0)

def _extract_targets_from_evidence(evidence_refs: List[str]) -> List[str]:
    targets: List[str] = []
    for ref in evidence_refs:
        if "://" in ref or "." in ref:
            targets.append(ref)
    return targets

def _promoted_findings_guard(
    result: EnrichmentResult,
    scope_graph: Optional[ScopeGraph],
    confidence_threshold: float,
    manifest_ref: Optional[ProvenanceRef],
) -> List[str]:
    warnings: List[str] = []
    filtered = []
    for finding in result.promoted_findings:
        evidence_refs = finding.evidence_refs or []
        if not evidence_refs:
            warnings.append(f"Finding '{finding.title}' missing evidence references.")
            continue

        if scope_graph:
            targets = _extract_targets_from_evidence(evidence_refs)
            if targets and not any(scope_graph.is_in_scope(target) for target in targets):
                warnings.append(f"Finding '{finding.title}' appears out of scope.")
                continue

        if _confidence_to_float(finding.confidence) < confidence_threshold:
            warnings.append(f"Finding '{finding.title}' below confidence threshold.")
            continue

        if not manifest_ref:
            warnings.append(f"Finding '{finding.title}' missing manifest provenance reference.")
            continue

        transcript_refs = _artifact_refs_for_transcript(result.artifacts)
        evidence_anchor_refs = _evidence_anchor_refs(evidence_refs, result.artifacts)
        if not transcript_refs:
            warnings.append(f"Finding '{finding.title}' missing transcript artifact provenance.")
            continue
        if not evidence_anchor_refs:
            warnings.append(f"Finding '{finding.title}' missing evidence anchor provenance.")
            continue

        provenance_refs = [manifest_ref] + transcript_refs + evidence_anchor_refs
        finding.raw_tool_fields.setdefault("provenance_refs", [r.__dict__ for r in provenance_refs])

        filtered.append(finding)

    result.promoted_findings = filtered
    return warnings

def _scope_gate_actions(
    actions: List[SuggestedAction],
    scope_graph: Optional[ScopeGraph],
) -> List[ParseWarning]:
    warnings: List[ParseWarning] = []
    if not scope_graph:
        return warnings

    for action in actions:
        for target in action.targets:
            if not scope_graph.is_in_scope(target):
                warnings.append(
                    ParseWarning(
                        artifact_path="decepticon_output",
                        reason=f"Suggested action '{action.action_id}' target out of scope: {target}",
                    )
                )
                break
    return warnings

def _artifact_refs_for_transcript(artifacts: List[ArtifactRef]) -> List[ProvenanceRef]:
    refs: List[ProvenanceRef] = []
    for artifact in artifacts:
        if artifact.kind in {"decepticon_output", "stdout", "stderr"}:
            refs.append(ProvenanceRef(kind="artifact", id=artifact.sha256, note=artifact.path))
    return refs

def _evidence_anchor_refs(evidence_refs: List[str], artifacts: List[ArtifactRef]) -> List[ProvenanceRef]:
    refs: List[ProvenanceRef] = []
    artifact_by_path = {artifact.path: artifact for artifact in artifacts}
    for ref in evidence_refs:
        ref_str = str(ref)
        if ref_str.startswith("http://") or ref_str.startswith("https://"):
            refs.append(ProvenanceRef(kind="endpoint", id=ref_str))
            continue
        artifact = artifact_by_path.get(ref_str)
        if artifact:
            refs.append(ProvenanceRef(kind="artifact", id=artifact.sha256, note=artifact.path))
            continue
        refs.append(ProvenanceRef(kind="artifact", id=ref_str))
    return refs

@dataclass
class DecepticonEnricher:
    """
    Consumes ReconBundles and uses an underlying engine (like Decepticon)
    to produce an EnrichmentResult.
    """
    adapter: DecepticonAdapter
    config: DecepticonConfig
    scope_graph: Optional[ScopeGraph] = None
    confidence_threshold: float = 0.8
    output_parser: Callable[[List[ArtifactRef]], Tuple[str, List[SuggestedAction], List[ParseWarning]]] = parse_decepticon_output
    manifest_ref: Optional[ProvenanceRef] = None

    def enrich(self, bundles: List[ReconBundle]) -> EnrichmentResult:
        """
        Processes one or more ReconBundles to generate enrichment data.
        """
        result = self.adapter.run_enrichment(bundles=bundles, config=self.config)
        return self._apply_parsing_and_guards(result)

    def enrich_from_artifacts(self, artifacts: List[ArtifactRef]) -> EnrichmentResult:
        """
        Replays enrichment by parsing existing artifacts without executing tools.
        """
        result = EnrichmentResult(artifacts=list(artifacts))
        return self._apply_parsing_and_guards(result)

    def _apply_parsing_and_guards(self, result: EnrichmentResult) -> EnrichmentResult:
        notes, actions, parse_warnings = self.output_parser(result.artifacts)
        result.notes_markdown = notes
        result.suggested_actions = actions

        scope_warnings = _scope_gate_actions(actions, self.scope_graph)
        result.warnings.extend(parse_warnings)
        result.warnings.extend(scope_warnings)

        promoted_warning_messages = _promoted_findings_guard(
            result=result,
            scope_graph=self.scope_graph,
            confidence_threshold=self.confidence_threshold,
            manifest_ref=self.manifest_ref,
        )
        for warning in promoted_warning_messages:
            result.warnings.append(ParseWarning(artifact_path="decepticon_output", reason=warning))

        if result.warnings:
            warnings_path = (
                self.adapter.runtime.artifacts_root
                / self.adapter.runtime.run_id
                / "decepticon"
                / "parse_warnings.txt"
            )
            warnings_path.parent.mkdir(parents=True, exist_ok=True)
            warnings_content = "\n".join([f"[{w.artifact_path}] {w.reason}" for w in result.warnings])
            warnings_path.write_text(warnings_content, encoding="utf-8")
            result.artifacts.append(
                ArtifactRef(
                    path=str(warnings_path),
                    kind="parse_warning",
                    sha256=hashlib.sha256(warnings_content.encode()).hexdigest(),
                )
            )

        return result

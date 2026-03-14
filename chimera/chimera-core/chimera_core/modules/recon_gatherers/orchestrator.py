import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

from chimera_core.runtime import Runtime
from chimera_core.modules.recon_gatherers.zypheron_adapter import ZypheronAdapter
from chimera_core.modules.recon_gatherers.vibepentester_adapter import VibePenTesterAdapter
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonAdapter, DecepticonConfig
from chimera_core.modules.recon_gatherers.enrichment.decepticon_enricher import DecepticonEnricher
from chimera_core.modules.recon_gatherers.sinks.recon_sink import ReconSink, PersistResult
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonClient
from chimera_core.modules.recon_gatherers.notify.summary import build_summary, build_enrichment_summary
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, Artifact, Finding
from chimera_core.modules.recon_gatherers.parsers.vibepentester_parser import parse_vibepentester_reports
from chimera_core.modules.recon_gatherers.replay_helpers import load_artifacts_for_run
from chimera_core.modules.runtime.run_manifest import RunManifest, write_manifest
from chimera_core import __version__
from chimera_core.modules.recon_gatherers.provenance.models import ProvenanceRecord, ProvenanceRef
from chimera_core.modules.recon_gatherers.provenance.stable_id import stable_id_for_finding, stable_id_for_action
from chimera_core.modules.recon_gatherers.provenance.write_provenance import write_provenance
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.recon_gatherers.quality.report_ready import apply_report_ready

def _hash_payload(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

def _scope_spec_hash(runtime: Runtime) -> str:
    payload = {
        "allowlist": runtime.scope_graph.allowed_domains,
        "denylist": runtime.scope_graph.denied_patterns,
        "rate_limits": {
            "requests_per_second": runtime.scope_policy.max_rps,
            "concurrency": runtime.scope_policy.max_concurrency,
        },
        "allow_ip_targets": runtime.scope_policy.allow_ip_targets,
        "allow_private_ips": runtime.scope_policy.allow_private_ips,
        "allowed_methods": runtime.scope_policy.allowed_methods,
    }
    return _hash_payload(payload)

def _config_to_payload(config: Any) -> Dict[str, Any]:
    if is_dataclass(config):
        data = asdict(config)
    else:
        data = dict(config.__dict__) if hasattr(config, "__dict__") else {"value": str(config)}
    for key, value in list(data.items()):
        if hasattr(value, "__fspath__"):
            data[key] = str(value)
    return data

def _write_manifest(runtime: Runtime, pipeline: List[str], targets: List[str], config_hashes: Dict[str, str]) -> Artifact:
    scope_hash = _scope_spec_hash(runtime)
    if getattr(runtime, "safety_policy", None):
        policy_payload = _policy_payload(runtime.safety_policy)
        config_hashes = dict(config_hashes)
        config_hashes["safety_policy"] = _hash_payload(policy_payload)
    manifest = RunManifest.create(
        run_id=runtime.run_id,
        pipeline=pipeline,
        targets=targets,
        scope_spec_hash=scope_hash,
        adapter_versions={"chimera_core": __version__},
        config_hashes=config_hashes,
    )
    manifest_payload = manifest.to_json().encode()
    manifest_path = write_manifest(manifest, runtime.artifacts_root / runtime.run_id)
    return Artifact(
        path=str(manifest_path),
        kind="run_manifest",
        sha256=hashlib.sha256(manifest_payload).hexdigest(),
    )

def _policy_payload(policy: SafetyPolicy) -> Dict[str, object]:
    return {
        "enforce_scope": policy.enforce_scope,
        "enforce_scope_hash": policy.enforce_scope_hash,
        "allow_external_execution": policy.allow_external_execution,
        "allowed_tools": sorted(policy.allowed_tools),
        "blocked_tools": sorted(policy.blocked_tools),
        "require_live_confirm": policy.require_live_confirm,
        "live_confirm_token": policy.live_confirm_token or "",
        "allow_destructive": policy.allow_destructive,
        "destructive_tool_markers": sorted(policy.destructive_tool_markers),
        "max_workers": policy.max_workers,
        "rps": policy.rps,
        "timeout_s": policy.timeout_s,
    }

def _manifest_ref(manifest_artifact: Artifact) -> ProvenanceRef:
    return ProvenanceRef(kind="manifest", id=manifest_artifact.sha256, note=manifest_artifact.path)

def _artifact_ref(artifact: Artifact) -> ProvenanceRef:
    return ProvenanceRef(kind="artifact", id=artifact.sha256, note=artifact.path)

def _bundle_ref(bundle: ReconBundle) -> ProvenanceRef:
    return ProvenanceRef(kind="bundle", id=f"{bundle.tool}:{bundle.run_id}")

def _find_artifact(bundle: ReconBundle, kind: str) -> Optional[Artifact]:
    return next((artifact for artifact in bundle.artifacts if artifact.kind == kind), None)

def _write_provenance_for_bundle(runtime: Runtime, records: List[ProvenanceRecord], bundle: ReconBundle) -> None:
    provenance_artifact = write_provenance(records, runtime.artifacts_root / runtime.run_id)
    bundle.artifacts.append(provenance_artifact)

def _require_manifest(manifest: Optional[RunManifest]) -> RunManifest:
    if not manifest:
        raise ValueError("Replay requires a RunManifest.")
    return manifest

def _assert_scope_hash(runtime: Runtime, manifest: RunManifest) -> None:
    if getattr(runtime, "safety_policy", None) and not runtime.safety_policy.enforce_scope_hash:
        return
    current_hash = _scope_spec_hash(runtime)
    if current_hash != manifest.scope_spec_hash:
        raise ValueError("Scope hash mismatch with manifest.")

def _confidence_to_float(value: Optional[str]) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except ValueError:
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return mapping.get(value.lower(), 0.0)

def run_zypheron_and_persist(
    target: str,
    runtime: Runtime,
    sink: ReconSink,
    notifier: Optional[ShannonClient] = None,
    program_handle: Optional[str] = None,
    replay: bool = False,
    manifest: Optional[RunManifest] = None,
) -> PersistResult:
    """
    Orchestrates a Zypheron scan, persists the results, and sends a notification.
    """
    manifest_artifact = None
    if replay:
        manifest = _require_manifest(manifest)
        _assert_scope_hash(runtime, manifest)
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=manifest.pipeline,
            targets=manifest.targets,
            config_hashes=manifest.config_hashes,
        )
    else:
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=["zypheron"],
            targets=[target],
            config_hashes={},
        )

    adapter = ZypheronAdapter(runtime=runtime)
    if replay:
        artifact_refs = load_artifacts_for_run(manifest.run_id, runtime.artifacts_root)
        stdout_path = next(
            (a.path for a in artifact_refs if a.kind == "stdout" and "zypheron" in a.path),
            "",
        )
        stderr_path = next(
            (a.path for a in artifact_refs if a.kind == "stderr" and "zypheron" in a.path),
            "",
        )
        stdout_content = Path(stdout_path).read_text(encoding="utf-8") if stdout_path else ""
        stderr_content = Path(stderr_path).read_text(encoding="utf-8") if stderr_path else ""
        observed_assets, services, findings = adapter._parse_zypheron_output(
            stdout_content, stderr_content, ["zypheron", "scan", target]
        )
        bundle = ReconBundle(
            run_id=runtime.run_id,
            target=target,
            tool="zypheron",
            observed_assets=observed_assets,
            services=services,
            findings=findings,
            artifacts=[
                Artifact(path=a.path, kind=a.kind, sha256=a.sha256) for a in artifact_refs
            ],
            parent_run_id=manifest.run_id,
        )
        if manifest_artifact:
            bundle.artifacts.append(manifest_artifact)
    else:
        # 1. Run the scan
        bundle = adapter.run_scan(target)
        if manifest_artifact:
            bundle.artifacts.append(manifest_artifact)

    records: List[ProvenanceRecord] = []
    manifest_ref = _manifest_ref(manifest_artifact) if manifest_artifact else None
    stdout_artifact = _find_artifact(bundle, "stdout")
    stderr_artifact = _find_artifact(bundle, "stderr")
    evidence_anchor = stderr_artifact.sha256 if stderr_artifact else (stdout_artifact.sha256 if stdout_artifact else "")
    for finding in bundle.findings:
        derived_from: List[ProvenanceRef] = []
        if manifest_ref:
            derived_from.append(manifest_ref)
        if stdout_artifact:
            derived_from.append(_artifact_ref(stdout_artifact))
        if stderr_artifact:
            derived_from.append(_artifact_ref(stderr_artifact))
        subject_id = stable_id_for_finding(finding, target=bundle.target, tool=bundle.tool, evidence_anchor=evidence_anchor)
        finding.raw_tool_fields.setdefault("provenance_subject_id", subject_id)
        finding.raw_tool_fields.setdefault("tool", bundle.tool)
        finding.raw_tool_fields.setdefault("target", bundle.target)
        records.append(
            ProvenanceRecord(
                subject_kind="finding",
                subject_id=subject_id,
                produced_by=bundle.tool,
                derived_from=tuple(derived_from),
                confidence=_confidence_to_float(finding.confidence),
            )
        )
    _write_provenance_for_bundle(runtime, records, bundle)
    apply_report_ready(findings=bundle.findings, scope_graph=runtime.scope_graph, target=bundle.target)

    # 2. Persist the results
    result = sink.persist(bundle)

    # 3. Send notification if a notifier is provided
    if notifier:
        summary = build_summary(bundle, result, program_handle=program_handle)
        notifier.send_recon_summary(summary)

    return result

def run_vibepentester_and_persist(
    target: str,
    runtime: Runtime,
    config: VibePenTesterConfig,
    sink: ReconSink,
    notifier: Optional[ShannonClient] = None,
    program_handle: Optional[str] = None,
    replay: bool = False,
    manifest: Optional[RunManifest] = None,
) -> PersistResult:
    """
    Orchestrates a VibePenTester scan, persists the results, and sends a notification.
    """
    manifest_artifact = None
    if replay:
        manifest = _require_manifest(manifest)
        _assert_scope_hash(runtime, manifest)
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=manifest.pipeline,
            targets=manifest.targets,
            config_hashes=manifest.config_hashes,
        )
    else:
        config_hashes = {"vibepentester": _hash_payload(_config_to_payload(config))}
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=["vibepentester"],
            targets=[target],
            config_hashes=config_hashes,
        )

    adapter = VibePenTesterAdapter(runtime=runtime)
    if replay:
        artifact_refs = load_artifacts_for_run(manifest.run_id, runtime.artifacts_root)
        report_artifacts = [
            Artifact(path=a.path, kind="report", sha256=a.sha256)
            for a in artifact_refs
            if "vibepentester" in a.path and a.kind == "report"
        ]
        findings, parse_warnings = parse_vibepentester_reports(report_artifacts)
        artifacts: List[Artifact] = [
            Artifact(path=a.path, kind=a.kind, sha256=a.sha256) for a in artifact_refs
        ]
        if parse_warnings:
            warnings_content = "\n".join([f"[{w.artifact_path}] {w.reason}" for w in parse_warnings])
            warnings_path = runtime.artifacts_root / runtime.run_id / "vibepentester" / "parse_warnings.txt"
            warnings_path.parent.mkdir(parents=True, exist_ok=True)
            warnings_path.write_text(warnings_content, encoding="utf-8")
            artifacts.append(
                Artifact(
                    path=str(warnings_path),
                    kind="parse_warning",
                    sha256=hashlib.sha256(warnings_content.encode()).hexdigest(),
                )
            )

        bundle = ReconBundle(
            run_id=runtime.run_id,
            target=target,
            tool="vibepentester",
            findings=findings,
            artifacts=artifacts,
            parent_run_id=manifest.run_id,
        )
        if manifest_artifact:
            bundle.artifacts.append(manifest_artifact)
    else:
        # 1. Run the scan
        bundle = adapter.run_scan(target_url=target, config=config)
        if manifest_artifact:
            bundle.artifacts.append(manifest_artifact)

    records = []
    manifest_ref = _manifest_ref(manifest_artifact) if manifest_artifact else None
    report_artifacts = [artifact for artifact in bundle.artifacts if artifact.kind == "report"]
    stdout_artifact = _find_artifact(bundle, "stdout")
    evidence_anchor = report_artifacts[0].sha256 if report_artifacts else ""
    for finding in bundle.findings:
        derived_from: List[ProvenanceRef] = []
        if manifest_ref:
            derived_from.append(manifest_ref)
        if stdout_artifact:
            derived_from.append(_artifact_ref(stdout_artifact))
        for report_artifact in report_artifacts:
            derived_from.append(_artifact_ref(report_artifact))
        subject_id = stable_id_for_finding(
            finding,
            target=bundle.target,
            tool=bundle.tool,
            evidence_anchor=evidence_anchor,
        )
        finding.raw_tool_fields.setdefault("provenance_subject_id", subject_id)
        finding.raw_tool_fields.setdefault("tool", bundle.tool)
        finding.raw_tool_fields.setdefault("target", bundle.target)
        records.append(
            ProvenanceRecord(
                subject_kind="finding",
                subject_id=subject_id,
                produced_by=bundle.tool,
                derived_from=tuple(derived_from),
                confidence=_confidence_to_float(finding.confidence),
            )
        )
    _write_provenance_for_bundle(runtime, records, bundle)
    apply_report_ready(findings=bundle.findings, scope_graph=runtime.scope_graph, target=bundle.target)

    # 2. Persist the results
    result = sink.persist(bundle)

    # 3. Send notification if a notifier is provided
    if notifier:
        summary = build_summary(bundle, result, program_handle=program_handle)
        notifier.send_recon_summary(summary)

    return result


def run_decepticon_and_persist(
    bundles: List[ReconBundle],
    runtime: Runtime,
    config: DecepticonConfig,
    sink: ReconSink,
    notifier: Optional[ShannonClient] = None,
    program_handle: Optional[str] = None,
    replay: bool = False,
    manifest: Optional[RunManifest] = None,
) -> PersistResult:
    """
    Runs Decepticon enrichment, persists artifacts and analysis, and notifies Shannon.
    """
    manifest_artifact = None
    if replay:
        manifest = _require_manifest(manifest)
        _assert_scope_hash(runtime, manifest)
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=manifest.pipeline,
            targets=manifest.targets,
            config_hashes=manifest.config_hashes,
        )
    else:
        config_hashes = {"decepticon": _hash_payload(_config_to_payload(config))}
        manifest_artifact = _write_manifest(
            runtime=runtime,
            pipeline=["decepticon"],
            targets=[bundle.target for bundle in bundles],
            config_hashes=config_hashes,
        )

    adapter = DecepticonAdapter(runtime=runtime)
    enricher = DecepticonEnricher(
        adapter=adapter,
        config=config,
        scope_graph=runtime.scope_graph,
        manifest_ref=_manifest_ref(manifest_artifact) if manifest_artifact else None,
    )
    if replay:
        artifact_refs = load_artifacts_for_run(manifest.run_id, runtime.artifacts_root)
        enrichment = enricher.enrich_from_artifacts(artifact_refs)
    else:
        enrichment = enricher.enrich(bundles=bundles)

    run_id = runtime.run_id
    if replay and manifest and manifest.targets:
        target = manifest.targets[0]
    else:
        target = bundles[0].target if bundles else "unknown"
    run_artifacts_dir = runtime.artifacts_root / run_id / "decepticon"
    run_artifacts_dir.mkdir(parents=True, exist_ok=True)

    notes_path = run_artifacts_dir / "notes.md"
    notes_path.write_text(enrichment.notes_markdown or "", encoding="utf-8")
    notes_sha = hashlib.sha256((enrichment.notes_markdown or "").encode()).hexdigest()

    actions_path = run_artifacts_dir / "suggested_actions.json"
    actions_payload = [action.__dict__ for action in enrichment.suggested_actions]
    actions_path.write_text(json.dumps(actions_payload, indent=2, sort_keys=True), encoding="utf-8")
    actions_sha = hashlib.sha256(actions_path.read_bytes()).hexdigest()

    artifacts: List[Artifact] = [
        Artifact(path=str(notes_path), kind="analysis_notes", sha256=notes_sha),
        Artifact(path=str(actions_path), kind="suggested_actions", sha256=actions_sha),
    ]
    artifacts.extend(
        [
            Artifact(path=ref.path, kind=ref.kind, sha256=ref.sha256)
            for ref in enrichment.artifacts
        ]
    )
    if manifest_artifact:
        artifacts.append(manifest_artifact)

    analysis_finding = Finding(
        title="Decepticon enrichment analysis",
        type="analysis",
        severity="info",
        confidence="high" if enrichment.notes_markdown else "medium",
        evidence_refs=[str(notes_path), str(actions_path)],
        reproduction=None,
        tags=["decepticon", "analysis"],
        raw_tool_fields={"suggested_actions": actions_payload},
    )

    findings = [analysis_finding] + enrichment.promoted_findings

    records: List[ProvenanceRecord] = []
    manifest_ref = _manifest_ref(manifest_artifact) if manifest_artifact else None
    transcript_artifacts = [
        artifact for artifact in artifacts if artifact.kind in {"decepticon_output", "stdout", "stderr"}
    ]
    transcript_ref = _artifact_ref(transcript_artifacts[0]) if transcript_artifacts else None
    bundle_refs = [_bundle_ref(bundle) for bundle in bundles]
    analysis_refs: List[ProvenanceRef] = []
    if manifest_ref:
        analysis_refs.append(manifest_ref)
    analysis_refs.append(_artifact_ref(Artifact(path=str(notes_path), kind="analysis_notes", sha256=notes_sha)))
    analysis_refs.append(_artifact_ref(Artifact(path=str(actions_path), kind="suggested_actions", sha256=actions_sha)))
    for artifact in transcript_artifacts:
        analysis_refs.append(_artifact_ref(artifact))

    analysis_id = stable_id_for_finding(
        analysis_finding,
        target=target,
        tool="decepticon",
        evidence_anchor=notes_sha,
    )
    analysis_finding.raw_tool_fields.setdefault("provenance_subject_id", analysis_id)
    analysis_finding.raw_tool_fields.setdefault("tool", "decepticon")
    analysis_finding.raw_tool_fields.setdefault("target", target)
    records.append(
        ProvenanceRecord(
            subject_kind="analysis",
            subject_id=analysis_id,
            produced_by="decepticon",
            derived_from=tuple(analysis_refs),
            confidence=_confidence_to_float(analysis_finding.confidence),
        )
    )

    for action in enrichment.suggested_actions:
        derived_from: List[ProvenanceRef] = []
        if manifest_ref:
            derived_from.append(manifest_ref)
        derived_from.extend(bundle_refs)
        for artifact in transcript_artifacts:
            derived_from.append(_artifact_ref(artifact))
        action_id = stable_id_for_action(
            action,
            source_artifact_id=transcript_ref.id if transcript_ref else None,
        )
        records.append(
            ProvenanceRecord(
                subject_kind="action",
                subject_id=action_id,
                produced_by="decepticon",
                derived_from=tuple(derived_from),
                confidence=action.confidence,
            )
        )

    for finding in enrichment.promoted_findings:
        raw_refs = finding.raw_tool_fields.get("provenance_refs", [])
        derived_from = tuple(
            ProvenanceRef(
                kind=ref.get("kind", "artifact"),
                id=ref.get("id", ""),
                note=ref.get("note"),
            )
            for ref in raw_refs
            if ref.get("id")
        )
        evidence_anchor = ""
        for ref in derived_from:
            if ref.kind in {"artifact", "service", "finding", "endpoint"}:
                evidence_anchor = ref.id
                break
        subject_id = stable_id_for_finding(
            finding,
            target=target,
            tool="decepticon",
            evidence_anchor=evidence_anchor,
        )
        finding.raw_tool_fields.setdefault("provenance_subject_id", subject_id)
        finding.raw_tool_fields.setdefault("tool", "decepticon")
        finding.raw_tool_fields.setdefault("target", target)
        records.append(
            ProvenanceRecord(
                subject_kind="finding",
                subject_id=subject_id,
                produced_by="decepticon",
                derived_from=derived_from,
                confidence=_confidence_to_float(finding.confidence),
            )
        )

    bundle = ReconBundle(
        run_id=run_id,
        target=target,
        tool="decepticon",
        findings=findings,
        artifacts=artifacts,
        parent_run_id=manifest.run_id if replay and manifest else None,
    )

    _write_provenance_for_bundle(runtime, records, bundle)
    apply_report_ready(findings=bundle.findings, scope_graph=runtime.scope_graph, target=target)

    result = sink.persist(bundle)

    if notifier:
        summary = build_enrichment_summary(
            target=target,
            run_id=run_id,
            suggested_actions=enrichment.suggested_actions,
            promoted_findings=enrichment.promoted_findings,
            persist_result=result,
            program_handle=program_handle,
            top_n=5,
        )
        notifier.send_recon_summary(summary)

    return result

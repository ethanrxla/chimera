from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.modules.recon_gatherers.enrichment.models import SuggestedAction
from chimera_core.modules.recon_gatherers.provenance.stable_id import (
    stable_id_for_action,
    stable_id_for_finding,
)


def test_stable_id_is_deterministic_across_ordering():
    action_a = SuggestedAction(
        action_id="scan",
        description="Scan endpoints",
        tool="curl",
        targets=["b.example.com", "a.example.com"],
        confidence=0.7,
    )
    action_b = SuggestedAction(
        action_id="scan",
        description="Scan endpoints",
        tool="curl",
        targets=["a.example.com", "b.example.com"],
        confidence=0.7,
    )

    id_a = stable_id_for_action(action_a, source_artifact_id="artifact-1")
    id_b = stable_id_for_action(action_b, source_artifact_id="artifact-1")

    assert id_a == id_b


def test_stable_id_changes_when_fields_change():
    finding = Finding(title="SQLi", type="vuln", severity="high")

    id_a = stable_id_for_finding(
        finding,
        target="example.com",
        tool="vibepentester",
        evidence_anchor="artifact-1",
    )
    id_b = stable_id_for_finding(
        Finding(title="SQLi", type="vuln", severity="medium"),
        target="example.com",
        tool="vibepentester",
        evidence_anchor="artifact-1",
    )

    assert id_a != id_b

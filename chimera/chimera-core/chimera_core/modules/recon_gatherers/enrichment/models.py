from dataclasses import dataclass, field
from typing import List

from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.modules.recon_gatherers.parsers.vibepentester_parser import ParseWarning

@dataclass
class ArtifactRef:
    """Reference to a stored artifact produced during enrichment."""
    path: str
    kind: str
    sha256: str

@dataclass
class SuggestedAction:
    """Represents a structured next action recommended by an enrichment engine."""
    action_id: str
    description: str
    tool: str
    targets: List[str]
    confidence: float

@dataclass
class EnrichmentResult:
    """Represents the output of an enrichment process."""
    notes_markdown: str = ""
    suggested_actions: List[SuggestedAction] = field(default_factory=list)
    promoted_findings: List[Finding] = field(default_factory=list)
    artifacts: List[ArtifactRef] = field(default_factory=list)
    warnings: List[ParseWarning] = field(default_factory=list)

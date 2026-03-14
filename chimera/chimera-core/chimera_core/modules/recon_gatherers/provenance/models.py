from dataclasses import dataclass
from typing import Optional, Tuple, Literal


@dataclass(frozen=True)
class ProvenanceRef:
    kind: Literal["artifact", "service", "asset", "endpoint", "finding", "bundle", "manifest"]
    id: str
    note: Optional[str] = None


@dataclass(frozen=True)
class ProvenanceRecord:
    subject_kind: Literal["finding", "action", "analysis"]
    subject_id: str
    produced_by: str
    derived_from: Tuple[ProvenanceRef, ...]
    confidence: Optional[float] = None
    created_at: Optional[str] = None

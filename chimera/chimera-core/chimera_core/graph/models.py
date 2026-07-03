from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    attrs: Dict[str, object] = field(default_factory=dict)


@dataclass
class GraphEdge:
    src: str
    dst: str
    label: str
    attrs: Dict[str, object] = field(default_factory=dict)


@dataclass
class EvidenceGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
        }

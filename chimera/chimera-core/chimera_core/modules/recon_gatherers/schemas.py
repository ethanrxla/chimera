from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ObservedAsset:
    type: str  # host, domain, url
    value: str
    source_tool: str

@dataclass
class Service:
    host: str
    port: int
    proto: str
    service: str
    banner: Optional[str] = None
    confidence: Optional[str] = None

@dataclass
class WebEndpoint:
    url: str
    method: Optional[str] = None
    params: List[str] = field(default_factory=list)
    discovered_by: Optional[str] = None

@dataclass
class Finding:
    title: str
    type: str  # vuln, misconfig, info
    severity: str  # none, low, med, high, critical
    confidence: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    reproduction: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw_tool_fields: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Artifact:
    path: str
    kind: str  # stdout, report, pcap, har
    sha256: str

@dataclass
class ReconBundle:
    run_id: str
    target: str
    tool: str
    observed_assets: List[ObservedAsset] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    web_endpoints: List[WebEndpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    parent_run_id: Optional[str] = None

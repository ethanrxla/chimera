from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class HttpResponseSummary:
    status_code: int
    headers: dict[str, str]
    body_excerpt: str
    body_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HexStrikeResult:
    call_id: str
    ok: bool
    error: str | None
    observed_targets: list[str]
    request_artifact_ref: str
    response_artifact_ref: str
    normalized_artifact_ref: str
    summary: HttpResponseSummary | dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if isinstance(self.summary, HttpResponseSummary):
            payload["summary"] = self.summary.to_dict()
        return payload

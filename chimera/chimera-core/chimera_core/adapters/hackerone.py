import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import requests
import time

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeSpec, ScopeItem, ScopeSource


@dataclass
class HackerOneAdapter:
    """
    Adapter for integrating with the HackerOne API, providing workflow methods
    for scope ingestion and report management.
    """
    runtime: Runtime


    def sync_structured_scopes(self, program_handle: str) -> ScopeSpec:
        path = f"/programs/{program_handle}/structured_scopes"
        response_data = self.runtime.http_get(service="hackerone", path=path).json()
        
        in_scope_items: List[ScopeItem] = []
        out_of_scope_items: List[ScopeItem] = []

        for item in response_data.get("data", []):
            attributes = item.get("attributes", {})
            asset_identifier = attributes.get("asset_identifier")
            asset_type = attributes.get("asset_type")
            eligible_for_submission = attributes.get("eligible_for_submission")
            # For H1, if not eligible_for_submission, it's out of scope
            if asset_identifier:
                scope_source = ScopeSource(provider="hackerone", structured_scope_id=item.get("id"))
                if eligible_for_submission:
                    in_scope_items.append(ScopeItem(
                        asset_identifier=asset_identifier,
                        asset_type=asset_type,
                        max_severity=attributes.get("max_severity"),
                        instructions=attributes.get("instructions"),
                        source=scope_source
                    ))
                else:
                    out_of_scope_items.append(ScopeItem(
                        asset_identifier=asset_identifier,
                        asset_type=asset_type,
                        reason="Out of scope per program policy",
                        source=scope_source
                    ))
        
        scope_spec = ScopeSpec(
            program_handle=program_handle,
            generated_at=datetime.now(timezone.utc).isoformat(),
            in_scope=in_scope_items,
            out_of_scope=out_of_scope_items,
        )

        # Cache the ScopeSpec locally
        cache_dir = self.runtime.artifacts_root / "chimera_state" / "programs" / program_handle
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "scope_spec.json"
        with open(cache_file, "w") as f:
            json.dump(scope_spec.to_dict(), f, indent=2)
        self.runtime.event_store.emit_event({
            "event_type": "hackerone_scope_synced",
            "payload": {
                "program_handle": program_handle,
                "cache_file": str(cache_file),
                "in_scope_count": len(in_scope_items),
                "out_of_scope_count": len(out_of_scope_items),
            },
        })
        return scope_spec

    def list_report_intents(self) -> List[Dict[str, Any]]:
        # Implementation for listing report intents
        pass

    def get_report_intent(self, intent_id: str) -> Dict[str, Any]:
        # Implementation for getting a specific report intent
        pass

    def update_report_intent(self, intent_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        # Implementation for updating a report intent
        pass

    def upload_intent_attachments(self, intent_id: str, files: List[str]) -> List[Dict[str, Any]]:
        # Implementation for uploading attachments to a report intent
        pass

    def submit_report_intent(self, intent_id: str) -> Dict[str, Any]:
        # Implementation for submitting a report intent
        pass

    def submit_report(self, team_handle: str, title: str, vulnerability_information: str) -> Dict[str, Any]:
        # Implementation for direct report submission
        pass


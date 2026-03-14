from __future__ import annotations

from typing import Dict, List


CAPABILITY_REGISTRY: Dict[str, List[str]] = {
    "api_rest": ["autoswagger", "bola_validator", "rate_limit_validator", "shannon"],
    "graphql": ["autoswagger", "shannon"],
    "web_app": ["strix", "browser", "shannon"],
    "subdomain": ["subfinder", "zypheron", "shannon"],
    "llm_endpoint": ["shannon"],
    "auth": ["jwt_validator", "decepticon", "shannon"],
}


def get_capabilities_for_target(asset_type: str, discovered_context: dict) -> List[str]:
    capabilities = list(CAPABILITY_REGISTRY.get(asset_type, []))
    context = discovered_context or {}

    if asset_type == "web_app" and context.get("javascript_heavy"):
        capabilities.insert(1, "vibepentester")
    if asset_type == "subdomain" and context.get("takeover_check"):
        capabilities.append("decepticon")
    if asset_type == "auth" and context.get("oauth_surface"):
        capabilities.insert(1, "rate_limit_validator")
    if asset_type == "api_rest" and context.get("authz_probe") and "bola_validator" not in capabilities:
        capabilities.insert(1, "bola_validator")

    seen = set()
    ordered: List[str] = []
    for capability in capabilities:
        if capability in seen:
            continue
        seen.add(capability)
        ordered.append(capability)
    return ordered

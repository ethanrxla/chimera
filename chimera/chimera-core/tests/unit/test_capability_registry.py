from chimera_core.capabilities.registry import get_capabilities_for_target


def test_registry_returns_default_api_sequence() -> None:
    capabilities = get_capabilities_for_target("api_rest", {})
    assert capabilities == ["autoswagger", "bola_validator", "rate_limit_validator", "shannon"]


def test_registry_reaches_extra_tools_when_context_matches() -> None:
    web_caps = get_capabilities_for_target("web_app", {"javascript_heavy": True})
    subdomain_caps = get_capabilities_for_target("subdomain", {"takeover_check": True})

    assert "browser" in web_caps
    assert "subfinder" in subdomain_caps

from chimera_core.hexstrike.catalog import get_tool_catalog, get_tool_spec


def test_hexstrike_catalog_contains_expected_tool_specs() -> None:
    catalog = get_tool_catalog()

    assert "nuclei" in catalog
    assert "masscan" in catalog
    assert "curl" in catalog
    assert "sqlmap" in catalog
    assert "checksec" in catalog
    assert "anew" in catalog
    assert "probe" in catalog
    assert "recon" in catalog
    assert catalog["nuclei"].route == "/api/tools/nuclei"
    assert catalog["masscan"].route == "/api/tools/masscan"
    assert catalog["curl"].route == "/api/tools/curl"
    assert catalog["probe"].route == "/api/probe"
    assert catalog["recon"].route == "/api/recon"


def test_hexstrike_catalog_marks_risk_tiers_and_target_fields() -> None:
    nuclei = get_tool_spec("nuclei")
    masscan = get_tool_spec("masscan")
    command = get_tool_spec("command")
    probe = get_tool_spec("probe")
    sqlmap = get_tool_spec("sqlmap")

    assert nuclei.risk_tier == "bounded_active"
    assert masscan.risk_tier == "bounded_active"
    assert command.risk_tier == "dangerous"
    assert sqlmap.risk_tier == "dangerous"
    assert probe.target_fields == ("endpoint",)

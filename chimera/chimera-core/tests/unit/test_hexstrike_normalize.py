from chimera_core.hexstrike.normalize import normalize_tool_output


def test_normalize_probe_output_emits_header_finding() -> None:
    findings = normalize_tool_output(
        "probe",
        {
            "endpoint": "https://example.com/login",
            "checks": {
                "csp": False,
                "x_frame": "",
                "auth_required": False,
            },
        },
        run_id="run-hx",
        scope_hash="scope-hx",
    )

    assert len(findings) == 1
    assert findings[0].tool_source == "hexstrike"
    assert findings[0].affected_target == "https://example.com/login"
    assert findings[0].finding_type == "CLICKJACKING"


def test_normalize_nuclei_output_emits_finding_from_match() -> None:
    findings = normalize_tool_output(
        "nuclei",
        {
            "results": [
                {
                    "info": {"name": "Reflected XSS", "severity": "high"},
                    "matched-at": "https://example.com/search?q=test",
                    "template-id": "xss-template",
                }
            ]
        },
        run_id="run-hx",
        scope_hash="scope-hx",
    )

    assert len(findings) == 1
    assert findings[0].title == "Reflected XSS"
    assert findings[0].severity == "high"
    assert findings[0].finding_type == "XSS"

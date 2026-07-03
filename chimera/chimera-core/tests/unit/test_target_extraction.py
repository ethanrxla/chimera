from chimera_core.target_extraction import extract_targets_from_command, extract_targets_from_params


def test_extract_targets_from_command_handles_urls_domains_and_ips() -> None:
    command = ["curl", "https://example.com", "api.example.com", "1.2.3.4", "--header", "x:y", "module.name"]
    assert extract_targets_from_command(command) == ["https://example.com", "api.example.com", "1.2.3.4"]


def test_extract_targets_from_params_splits_targets_field() -> None:
    params = {"targets": "https://example.com,https://api.example.com", "endpoint": "https://ignored.example.com"}
    assert extract_targets_from_params(params, ("targets",)) == ["https://example.com", "https://api.example.com"]

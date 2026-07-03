from pathlib import Path

from chimera_core.finding_cache import FindingCache, fingerprint_claim


def test_fingerprint_claim_is_stable() -> None:
    a = fingerprint_claim(claim_type="open_redirect", target="https://example.com/login", endpoint="/login", params=["redirect"])
    b = fingerprint_claim(claim_type="open_redirect", target="https://example.com/login", endpoint="/login", params=["redirect"])
    assert a == b


def test_finding_cache_stores_and_retrieves_verified_entries(tmp_path: Path) -> None:
    cache = FindingCache(tmp_path / "finding_cache.json")
    fingerprint = fingerprint_claim(claim_type="open_redirect", target="https://example.com/login", endpoint="/login", params=["redirect"])
    finding = {"finding_id": "f1", "title": "Open Redirect", "status": "verified"}
    cache.put_verified(fingerprint, finding)

    assert cache.get_verified(fingerprint) == finding

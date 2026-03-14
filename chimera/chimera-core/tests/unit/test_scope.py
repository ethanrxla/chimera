import pytest
from chimera_core.scope import ScopeGraph

def test_scope_allowlist_allows_subdomains():
    """
    Tests that a base domain in the allowlist correctly allows for subdomains.
    """
    scope_manifest = {
        "allowlist": ["example.com"],
        "denylist": []
    }
    scope_graph = ScopeGraph(scope_manifest)

    assert scope_graph.is_in_scope("http://example.com") is True, "Exact domain should be in scope"
    assert scope_graph.is_in_scope("https://www.example.com") is True, "Subdomain should be in scope"
    assert scope_graph.is_in_scope("ftp://api.v1.example.com/path") is True, "Complex subdomain URL should be in scope"

def test_scope_allowlist_blocks_unrelated_domains():
    """
    Tests that the allowlist correctly blocks domains that do not match.
    """
    scope_manifest = {
        "allowlist": ["example.com"],
        "denylist": []
    }
    scope_graph = ScopeGraph(scope_manifest)
    
    assert scope_graph.is_in_scope("http://evil.com") is False, "Unrelated domain should be out of scope"
    assert scope_graph.is_in_scope("http://example.com.net") is False, "Similar-looking domain should be out of scope"

def test_scope_denylist_overrides_allowlist():
    """
    Tests that a denylist pattern correctly blocks a target that would
    otherwise be allowed by the allowlist.
    """
    scope_manifest = {
        "allowlist": ["example.com"],
        "denylist": ["admin.example.com"]
    }
    scope_graph = ScopeGraph(scope_manifest)

    assert scope_graph.is_in_scope("http://www.example.com") is True, "Non-denied subdomain should be in scope"
    assert scope_graph.is_in_scope("http://admin.example.com") is False, "Denied subdomain should be out of scope"
    assert scope_graph.is_in_scope("https://sub.admin.example.com") is False, "Subdomain of a denied domain should be out of scope"

def test_url_canonicalization_is_stable():
    """
    Tests that the canonicalization function produces a stable, predictable
    representation for equivalent URLs.
    """
    from chimera_core.scope import canonicalize_url

    # Scheme and case normalization
    assert canonicalize_url("https://Example.com") == "https://example.com/"
    
    # Port normalization
    assert canonicalize_url("http://test.com:80") == "http://test.com/"
    assert canonicalize_url("https://test.com:443") == "https://test.com/"
    assert canonicalize_url("https://test.com:8443") == "https://test.com:8443/"

    # Trailing slash and fragment removal
    assert canonicalize_url("https://test.com/path") == "https://test.com/path/"
    assert canonicalize_url("https://test.com/path/") == "https://test.com/path/"
    assert canonicalize_url("https://test.com/path#fragment") == "https://test.com/path/"
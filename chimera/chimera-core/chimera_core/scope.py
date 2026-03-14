"""
Handles the parsing, normalization, and representation of the testing scope.

This module converts a user-provided scope manifest (e.g., from a YAML file)
into a canonical, efficient internal representation used for guardrails and
decision-making throughout the pipeline.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field

@dataclass
class ScopeSource:
    provider: str
    structured_scope_id: str

@dataclass
class ScopeItem:
    asset_identifier: str
    asset_type: str
    source: ScopeSource
    max_severity: Optional[str] = None
    instructions: Optional[str] = None
    reason: Optional[str] = None # For out-of-scope items

    def to_dict(self):
        return {
            "asset_identifier": self.asset_identifier,
            "asset_type": self.asset_type,
            "max_severity": self.max_severity,
            "instructions": self.instructions,
            "reason": self.reason,
            "source": self.source.__dict__,
        }

@dataclass
class ScopeSpec:
    program_handle: str
    generated_at: str
    in_scope: List[ScopeItem] = field(default_factory=list)
    out_of_scope: List[ScopeItem] = field(default_factory=list)

    def to_dict(self):
        return {
            "program_handle": self.program_handle,
            "generated_at": self.generated_at,
            "in_scope": [item.to_dict() for item in self.in_scope],
            "out_of_scope": [item.to_dict() for item in self.out_of_scope],
        }


class ScopePolicy:
    """
    Defines the rules and constraints of the run, such as rate limits and
    allowed methods.
    """
    def __init__(self, config: Dict[str, Any]):
        self.max_rps = config.get("rate_limits", {}).get("requests_per_second", 10)
        self.max_concurrency = config.get("rate_limits", {}).get("concurrency", 5)
        self.allowed_methods = config.get("allowed_methods", ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
        self.allow_ip_targets = config.get("allow_ip_targets", True)
        self.allow_private_ips = config.get("allow_private_ips", True)
        # In the future, this can hold more complex rules.

class ScopeGraph:
    """
    An efficient representation of the targets in scope (allowlist) and out of
    scope (denylist).

    Future Implementation:
    - Domains will be stored in a Trie for efficient subdomain/suffix matching.
    - IP ranges will be stored in an Interval Tree/Set for fast CIDR checks.
    """
    def __init__(self, config: Dict[str, Any]):
        self.allowed_domains: List[str] = config.get("allowlist", [])
        self.denied_patterns: List[str] = config.get("denylist", [])
        # TODO: Add Trie for domains and Interval Set for IPs.

    def is_in_scope(self, target: str) -> bool:
        """
        Checks if a given target (e.g., a URL, domain, or IP) is within the
        defined scope. This is a critical guardrail.
        """
        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            if not hostname: # Could be a bare domain or invalid
                hostname = target.split('/')[0]
        except ValueError:
            hostname = target # Assume it's a bare domain

        def _normalize_allowed(entry: str) -> str:
            try:
                parsed = urlparse(entry)
                if parsed.hostname:
                    return parsed.hostname
            except Exception:
                pass
            return entry.split('/')[0]

        allowed_hosts = [_normalize_allowed(entry) for entry in self.allowed_domains]
        is_allowed = any(hostname == allowed or hostname.endswith(f".{allowed}") for allowed in allowed_hosts)
        is_denied = any(denied in hostname for denied in self.denied_patterns) # Deny is still substring for now
        return is_allowed and not is_denied

def normalize_scope(scope_manifest: Dict[str, Any]) -> (ScopeGraph, ScopePolicy):
    """
    Parses a raw scope manifest dictionary and returns a structured,
    normalized ScopeGraph and ScopePolicy.
    """
    graph = ScopeGraph(scope_manifest)
    policy = ScopePolicy(scope_manifest)
    return graph, policy

def canonicalize_url(url: str) -> str:
    """
    Converts a URL into a stable, canonical form.
    - Ensures scheme and netloc are lowercase
    - Removes default ports (80 for http, 443 for https)
    - Ensures the path has a trailing slash
    - Removes query params, fragments, and user info
    """
    try:
        parts = urlparse(url.strip())
        
        # Normalize scheme and netloc to lowercase
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        
        # Remove default port numbers
        if (scheme == "http" and netloc.endswith(':80')) or \
           (scheme == "https" and netloc.endswith(':443')):
            netloc = netloc.rsplit(':', 1)[0]
            
        # Ensure path has a trailing slash if it's not empty
        path = parts.path
        if not path:
            path = '/'
        elif not path.endswith('/'):
            path += '/'
            
        # Reconstruct without query, fragment, or user info
        return f"{scheme}://{netloc}{path}"

    except Exception:
        # If parsing fails, return a simplified lowercase version
        return url.lower()

"""
Manages the stateful "memory" for a single Chimera run.

The RunContext tracks what has already been discovered, tested, and found,
preventing the agent from looping, repeating work, or losing valuable
information. It is persisted locally and can be streamed to a remote
backend like Supabase.
"""
from typing import Set, Dict, Any

class RunContext:
    """
    Holds all stateful information for the current run.
    """
    def __init__(self, job_id: str):
        self.job_id = job_id

        # A set of canonical URLs that have been visited.
        # Future: Use a Bloom Filter for memory-efficient checks at scale.
        self.visited_urls: Set[str] = set()

        # Maps a host to its current operational stats (for rate limiting, etc.).
        self.host_stats: Dict[str, Dict[str, Any]] = {}

        # An index mapping an artifact's hash to its storage reference (path).
        self.artifact_index: Dict[str, str] = {}

        # An index mapping a finding's stable hash to its ID for deduplication.
        self.finding_dedupe_index: Dict[str, str] = {}

    def add_visited_url(self, url: str):
        """Adds a URL to the set of visited URLs."""
        # TODO: Canonicalize the URL before adding.
        self.visited_urls.add(url)

    def has_visited(self, url: str) -> bool:
        """Checks if a URL has already been visited."""
        # TODO: Canonicalize the URL before checking.
        return url in self.visited_urls

    def log_artifact(self, artifact_hash: str, storage_ref: str):
        """Logs a discovered artifact."""
        self.artifact_index[artifact_hash] = storage_ref

    def is_duplicate_finding(self, finding_hash: str) -> bool:
        """Checks if a finding with the given hash has already been seen."""
        return finding_hash in self.finding_dedupe_index

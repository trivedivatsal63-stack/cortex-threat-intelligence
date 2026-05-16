"""
Deduplication utilities to prevent storing duplicate intelligence data.
Uses content hashing for efficient duplicate detection.

WHY THIS EXISTS: The same CVE, article, or threat might appear in multiple
feeds. Deduplication ensures we don't waste storage or AI processing on
repeated data.
"""

import hashlib
import json
from typing import Optional, Set, Dict, Any
from datetime import datetime
from loguru import logger


def compute_content_hash(content: str) -> str:
    """
    Create a SHA-256 hash of content for dedup comparison.
    Handles both string and dict content by normalizing first.
    """
    if isinstance(content, dict):
        content = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_article_hash(title: str, url: str, published_date: Optional[str] = None) -> str:
    """
    Generate a unique hash for an article based on its title and URL.
    This is the primary dedup key for articles.
    """
    content = f"{title}|{url}|{published_date or ''}"
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def compute_cve_hash(cve_id: str) -> str:
    """
    CVE IDs are already unique identifiers, but we hash for consistency.
    """
    return hashlib.md5(cve_id.encode("utf-8")).hexdigest()


def compute_ioc_hash(ioc_value: str, ioc_type: str) -> str:
    """
    Create a hash for an IOC (IP, domain, hash, URL).
    """
    content = f"{ioc_value}|{ioc_type}"
    return hashlib.md5(content.encode("utf-8")).hexdigest()


class InMemoryDedupTracker:
    """
    Lightweight in-memory dedup tracker for a single run.
    Prevents processing the same item twice within one execution.
    
    Not for persistent dedup - that's handled by database unique constraints.
    """

    def __init__(self):
        self._seen: Set[str] = set()

    def is_duplicate(self, item_hash: str) -> bool:
        """Check if an item was already seen in this session."""
        return item_hash in self._seen

    def mark_seen(self, item_hash: str) -> None:
        """Mark an item as seen."""
        self._seen.add(item_hash)

    def check_and_mark(self, item_hash: str) -> bool:
        """Check and mark in one call. Returns True if already seen."""
        if item_hash in self._seen:
            return True
        self._seen.add(item_hash)
        return False

    def size(self) -> int:
        return len(self._seen)


# Global shared tracker for a pipeline run
global_dedup = InMemoryDedupTracker()

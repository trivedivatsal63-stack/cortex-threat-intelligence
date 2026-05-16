"""
Generic API-based collector for sources that provide REST APIs.
Handles API authentication, pagination, and response parsing.

WHY THIS EXISTS: Many sources (GitHub Security Advisories, AlienVault OTX,
AbuseIPDB, etc.) provide REST APIs. This generic collector can be configured
for any JSON-based API with minimal code.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from loguru import logger

from collectors.base import BaseCollector
from config.sources import DataSource
from config.settings import config
from utils.dedup import compute_article_hash, compute_ioc_hash
from utils.normalizer import extract_cve_ids, extract_iocs


class APICollector(BaseCollector):
    """
    Generic collector for REST API data sources.
    Supports: GET requests, API key headers, pagination, JSON responses.
    
    Specific source configurations define behavior via DataSource params.
    """
    
    def __init__(self, source: DataSource):
        super().__init__(source)
        # Handle API-specific authentication headers
        if source.name == "AlienVault OTX":
            self.headers["X-OTX-API-Key"] = config.database.supabase_key
        elif source.name == "AbuseIPDB":
            self.headers["Key"] = config.database.supabase_key
        elif source.name == "GitHub Security Advisories":
            self.headers["Accept"] = "application/vnd.github+json"
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch data from the API endpoint."""
        raw = await self.fetch_url(self.source.url, params=self.source.params)
        if not raw:
            self.log_collection_result(0, False)
            return []
        
        return self.parse(raw)
    
    def parse(self, raw_data: str) -> List[Dict[str, Any]]:
        """
        Parse JSON API response.
        Source-specific logic based on source name.
        """
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from {self.source.name}")
            return []
        
        handler = getattr(self, f"_parse_{self._get_source_key()}", None)
        if handler:
            return handler(data)
        
        # Default: treat as list of items or single item
        if isinstance(data, list):
            return [self._generic_parse(item) for item in data[:50]]
        elif isinstance(data, dict):
            return [self._generic_parse(data)]
        return []
    
    def _get_source_key(self) -> str:
        """Convert source name to method-friendly key."""
        return self.source.name.lower().replace(" ", "_").replace("-", "_")
    
    def _generic_parse(self, item: Dict) -> Dict[str, Any]:
        """Generic parser for unstructured JSON APIs."""
        return self.normalize_item({
            "title": item.get("title", item.get("name", item.get("id", ""))),
            "url": item.get("url", item.get("link", item.get("html_url", ""))),
            "content": json.dumps(item, default=str)[:5000],
            "content_hash": compute_article_hash(
                str(item.get("title", "")), 
                str(item.get("url", "")),
            ),
        })
    
    def _parse_github_security_advisories(self, data: List) -> List[Dict]:
        """Parse GitHub Security Advisory API response."""
        items = []
        for advisory in data:
            try:
                ghsa_id = advisory.get("ghsa_id", "")
                cve_ids_list = advisory.get("cve_ids", [])
                severity = advisory.get("severity", "")
                
                content_hash = compute_article_hash(
                    advisory.get("summary", ""), 
                    advisory.get("html_url", ""),
                )
                
                items.append(self.normalize_item({
                    "title": f"[{severity}] {advisory.get('summary', '')}",
                    "url": advisory.get("html_url", ""),
                    "description": advisory.get("description", ""),
                    "cve_ids": cve_ids_list,
                    "severity": severity,
                    "published_date": advisory.get("published_at", ""),
                    "updated_date": advisory.get("updated_at", ""),
                    "content_hash": content_hash,
                    "metadata": {
                        "ghsa_id": ghsa_id,
                        "advisory_type": "github",
                        "identifiers": advisory.get("identifiers", []),
                        "cvss_score": advisory.get("cvss", {}).get("score"),
                    },
                }))
            except Exception as e:
                logger.warning(f"Error parsing GitHub advisory: {e}")
                continue
        return items
    
    def _parse_urlhaus(self, data: Dict) -> List[Dict]:
        """Parse URLhaus API response."""
        items = []
        for url_entry in data.get("urls", []):
            try:
                url = url_entry.get("url", "")
                ioc_hash = compute_ioc_hash(url, "url")
                
                items.append(self.normalize_item({
                    "ioc_value": url,
                    "ioc_type": "url",
                    "ioc_hash": ioc_hash,
                    "threat_type": url_entry.get("threat", ""),
                    "source": "URLHaus",
                    "tags": url_entry.get("tags", []),
                    "date_added": url_entry.get("date_added", ""),
                }))
            except Exception:
                continue
        return items
    
    def _parse_openphish(self, data: str) -> List[Dict]:
        """Parse OpenPhish feed (list of URLs, one per line)."""
        items = []
        urls = data.strip().split('\n')
        for url in urls[:100]:  # Limit to 100 most recent
            url = url.strip()
            if url:
                ioc_hash = compute_ioc_hash(url, "phishing_url")
                items.append(self.normalize_item({
                    "ioc_value": url,
                    "ioc_type": "url",
                    "ioc_hash": ioc_hash,
                    "threat_type": "phishing",
                    "source": "OpenPhish",
                }))
        return items

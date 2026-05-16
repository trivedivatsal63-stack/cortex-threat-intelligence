"""
NVD (National Vulnerability Database) CVE Collector.
Fetches the latest CVEs from the official NVD API 2.0.

WHY THIS EXISTS: NVD is the authoritative US government source for
CVE data. This collector ensures we track ALL new vulnerabilities
with CVSS scores, exploitability data, and affected products.
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from loguru import logger
import json

from collectors.base import BaseCollector
from config.sources import DataSource
from config.settings import config
from utils.dedup import compute_cve_hash


class NVDCollector(BaseCollector):
    """
    Collects CVEs from the NVD API 2.0.
    
    NVD API Rate Limit: 10 requests per 60 seconds (for free tier).
    We handle this with appropriate delays between requests.
    
    The API returns CVEs with CVSS scores, descriptions, references,
    and affected product information.
    """
    
    def __init__(self, source: DataSource):
        super().__init__(source)
        # Add NVD-specific headers
        self.headers["apiKey"] = config.database.supabase_key  # Optional but helps rate limits
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch recent CVEs from NVD API."""
        # Calculate date range for lookback
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=self.source.lookback_days)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 50,
            "startIndex": 0,
        }
        
        all_cves = []
        total_results = None
        
        # Fetch pages of results
        while True:
            raw_data = await self.fetch_url(self.source.url, params=params)
            if not raw_data:
                break
            
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse NVD JSON response")
                break
            
            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"NVD: {total_results} CVEs to fetch")
            
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                parsed = self._parse_cve(cve_data)
                if parsed:
                    all_cves.append(parsed)
            
            # Check if there are more pages
            start_index = params["startIndex"] + params["resultsPerPage"]
            if start_index >= total_results:
                break
            
            params["startIndex"] = start_index
            
            # Rate limit: wait between page requests
            await asyncio.sleep(6.0)
        
        self.log_collection_result(len(all_cves))
        return all_cves
    
    def parse(self, raw_data: str) -> List[Dict[str, Any]]:
        """Parse a single NVD API response (used for testing)."""
        try:
            data = json.loads(raw_data)
            results = []
            for vuln in data.get("vulnerabilities", []):
                parsed = self._parse_cve(vuln.get("cve", {}))
                if parsed:
                    results.append(parsed)
            return results
        except Exception as e:
            logger.error(f"Error parsing NVD data: {e}")
            return []
    
    def _parse_cve(self, cve_data: Dict) -> Optional[Dict[str, Any]]:
        """Extract structured data from a single CVE entry."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
            
            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS scores
            metrics = cve_data.get("metrics", {})
            
            # CVSS v3.1 (preferred)
            cvss_v31 = metrics.get("cvssMetricV31", [{}])
            cvss_v3_score = None
            severity = None
            attack_vector = None
            if cvss_v31 and cvss_v31[0]:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                attack_vector = cvss_data.get("attackVector")
            
            # Fallback to CVSS v3.0
            if cvss_v3_score is None:
                cvss_v30 = metrics.get("cvssMetricV30", [{}])
                if cvss_v30 and cvss_v30[0]:
                    cvss_data = cvss_v30[0].get("cvssData", {})
                    cvss_v3_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                    attack_vector = cvss_data.get("attackVector")
            
            # CVSS v2.0
            cvss_v2 = metrics.get("cvssMetricV2", [{}])
            cvss_v2_score = None
            if cvss_v2 and cvss_v2[0]:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_v2_score = cvss_data.get("baseScore")
            
            # Extract affected products
            configurations = cve_data.get("configurations", [])
            affected_vendors = set()
            affected_products = set()
            for config_node in configurations:
                nodes = config_node.get("nodes", [])
                for node in nodes:
                    matches = node.get("cpeMatch", [])
                    for match in matches:
                        criteria = match.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            affected_vendors.add(parts[3])
                            affected_products.add(parts[4])
            
            # Extract exploit references
            references = cve_data.get("references", [])
            exploit_refs = []
            for ref in references:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                if "Exploit" in tags or "Vendor Advisory" in tags:
                    exploit_refs.append(url)
                # Check if any reference mentions exploit
                if "exploit" in url.lower():
                    exploit_refs.append(url)
            
            # Exploit availability: check by presence of exploit tags
            exploit_available = any("Exploit" in ref.get("tags", []) for ref in references)
            
            # Create hash
            cve_hash = compute_cve_hash(cve_id)
            
            return self.normalize_item({
                "cve_id": cve_id,
                "cve_hash": cve_hash,
                "description": description,
                "cvss_v2_score": cvss_v2_score,
                "cvss_v3_score": cvss_v3_score,
                "severity": severity,
                "exploit_available": exploit_available,
                "exploit_references": exploit_refs[:10] if exploit_refs else None,
                "affected_vendors": list(affected_vendors)[:20] if affected_vendors else None,
                "affected_products": list(affected_products)[:20] if affected_products else None,
                "attack_vector": attack_vector,
                "published_date": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
                "content": description,
            })
        except Exception as e:
            logger.warning(f"Error parsing CVE {cve_data.get('id', 'unknown')}: {e}")
            return None

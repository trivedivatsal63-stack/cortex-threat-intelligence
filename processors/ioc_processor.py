"""
IOC (Indicators of Compromise) Processor.
Extracts, validates, and deduplicates IOCs from collected data.

WHY THIS EXISTS: IOCs are critical for threat detection (blocking IPs,
domains, hashes in firewalls, SIEMs, and EDRs). This processor
extracts them from articles and CVE data, normalizes their format,
and prepares them for database storage.
"""

import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger
from ipaddress import ip_address, IPv4Address

from utils.dedup import compute_ioc_hash, global_dedup
from utils.normalizer import extract_iocs


class IOCProcessor:
    """
    Processes and validates Indicators of Compromise.
    
    Features:
    - Auto-extraction from article/CVE text
    - IP address validation (RFC 1918 filtering)
    - Domain format validation
    - Hash type detection (MD5 vs SHA1 vs SHA256)
    - Deduplication
    - Confidence scoring
    """
    
    # Private/reserved IP ranges to filter out
    PRIVATE_IPS = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
    ]
    
    def __init__(self):
        self.processed_count = 0
    
    def process(self, articles: List[Dict], cves: List[Dict]) -> List[Dict]:
        """
        Extract and process IOCs from articles and CVEs.
        Returns deduplicated list of validated IOCs.
        """
        iocs = []
        
        # Extract from articles
        for article in articles:
            text = f"{article.get('title', '')} {article.get('cleaned_content', '')}"
            extracted = extract_iocs(text)
            for ioc_type, values in extracted.items():
                for value in values if isinstance(values, list) else [values]:
                    if isinstance(value, tuple):
                        value, hash_type = value
                    else:
                        hash_type = None
                    
                    ioc = self._create_ioc(value, ioc_type, article.get("source", ""),
                                          article.get("url", ""), hash_type=hash_type)
                    if ioc:
                        iocs.append(ioc)
        
        # Extract from CVE descriptions        
        for cve in cves:
            text = cve.get("description", "")
            extracted = extract_iocs(text)
            for ioc_type, values in extracted.items():
                for value in values if isinstance(values, list) else [values]:
                    if isinstance(value, tuple):
                        value, hash_type = value
                    else:
                        hash_type = None
                    
                    ioc = self._create_ioc(value, ioc_type, f"CVE:{cve.get('cve_id', '')}",
                                          "", hash_type=hash_type,
                                          threat_type=cve.get("ai_classification"))
                    if ioc:
                        iocs.append(ioc)
        
        # Deduplicate
        deduplicated = self._deduplicate(iocs)
        
        self.processed_count += len(deduplicated)
        logger.info(f"IOC processing: {len(iocs)} raw -> {len(deduplicated)} unique")
        
        return deduplicated
    
    def _create_ioc(self, value: str, ioc_type: str, source: str, source_url: str,
                    hash_type: str = None, threat_type: str = None) -> Optional[Dict]:
        """Create a validated IOC entry."""
        if not value:
            return None
        
        value = value.strip()
        
        # Validate IP addresses
        if ioc_type == "ips":
            if not self._is_valid_public_ip(value):
                return None
        
        # Validate domains
        if ioc_type == "domains":
            if not self._is_valid_domain(value):
                return None
        
        ioc_hash = compute_ioc_hash(value, ioc_type)
        
        return {
            "ioc_value": value,
            "ioc_type": ioc_type.rstrip('s'),  # Normalize: ips -> ip, domains -> domain
            "ioc_hash": ioc_hash,
            "threat_type": threat_type or "unknown",
            "source": source or "auto-extracted",
            "source_url": source_url,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "reference_count": 1,
            "tags": [ioc_type.rstrip('s'), source.lower().replace(" ", "-")],
            "is_active": True,
            "confidence": 0.7 if source else 0.5,
            "metadata": {
                "hash_type": hash_type,
                "extraction_method": "ai" if source else "regex",
            },
        }
    
    def _is_valid_public_ip(self, ip: str) -> bool:
        """Check if an IP is valid and not in private/reserved ranges."""
        try:
            addr = ip_address(ip)
            if not isinstance(addr, IPv4Address):
                return False
            # Filter private and reserved ranges
            return not (addr.is_private or addr.is_loopback or 
                       addr.is_link_local or addr.is_multicast or
                       addr.is_unspecified or addr.is_reserved)
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Basic domain validation.
        Filters out obvious non-domains and TLD-only entries.
        """
        if not domain or len(domain) < 4:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', domain):
            return False
        # Filter common false positives
        false_positives = [
            "example.com", "example.org", "example.net",
            "localhost", "test.com", "domain.com",
        ]
        if domain.lower() in false_positives:
            return False
        # Filter common benign domains
        benign_tlds = [".gov", ".edu", ".mil"]
        if any(domain.endswith(tld) for tld in benign_tlds):
            # Could still be malicious, but let's be conservative
            pass
        return True
    
    def _deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs, keeping the earliest seen."""
        seen = {}
        for ioc in iocs:
            key = ioc["ioc_hash"]
            if key not in seen:
                seen[key] = ioc
            else:
                # Update reference count
                seen[key]["reference_count"] += 1
        
        return list(seen.values())

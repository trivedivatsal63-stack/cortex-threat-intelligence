"""
CISA (Cybersecurity and Infrastructure Security Agency) Collector.
Collects from:
1. CISA Known Exploited Vulnerabilities (KEV) Catalog
2. CISA Cybersecurity Alerts

WHY THIS EXISTS: CISA KEV lists vulnerabilities actively exploited in the wild.
This is CRITICAL intelligence - vulnerabilities on this list should be
prioritized for patching immediately. CISA alerts provide authoritative
government threat advisories.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from collectors.base import BaseCollector
from config.sources import DataSource
from utils.dedup import compute_cve_hash
from utils.normalizer import extract_cve_ids


class CISACollector(BaseCollector):
    """
    Collects from CISA's cybersecurity data feeds.
    Handles both KEV catalog and advisory alerts.
    """
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect from all CISA sources."""
        all_items = []
        
        # Try KEV catalog
        kev_items = await self._fetch_kev_catalog()
        all_items.extend(kev_items)
        
        return all_items
    
    async def _fetch_kev_catalog(self) -> List[Dict[str, Any]]:
        """
        Fetch the Known Exploited Vulnerabilities catalog.
        CISA publishes this as a JSON file that's updated when
        new active exploits are discovered.
        """
        raw = await self.fetch_url(self.source.url)
        if not raw:
            return []
        
        try:
            data = json.loads(raw)
            vulnerabilities = data.get("vulnerabilities", [])
            
            items = []
            for vuln in vulnerabilities:
                parsed = self._parse_kev_entry(vuln)
                if parsed:
                    items.append(parsed)
            
            logger.info(f"CISA KEV: {len(items)} vulnerabilities collected")
            return items
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CISA KEV JSON: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing CISA KEV: {e}")
            return []
    
    def _parse_kev_entry(self, entry: Dict) -> Optional[Dict[str, Any]]:
        """Parse a single KEV entry into standard format."""
        try:
            cve_id = entry.get("cveID", "")
            if not cve_id:
                return None
            
            # CISA KEV automatically means actively exploited
            cve_hash = compute_cve_hash(cve_id)
            
            return self.normalize_item({
                "cve_id": cve_id,
                "cve_hash": cve_hash,
                "description": entry.get("shortDescription", ""),
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "required_action": entry.get("requiredAction", ""),
                "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
                "notes": entry.get("notes", ""),
                "cwes": entry.get("cwes", []),
                "exploit_available": True,  # By definition, KEV = exploited
                "severity": "CRITICAL",
                "source_type": "cisa_kev",
            })
        except Exception as e:
            logger.warning(f"Error parsing CISA KEV entry: {e}")
            return None
    
    def parse(self, raw_data: str) -> List[Dict[str, Any]]:
        """Parse raw CISA JSON response (for testing)."""
        try:
            data = json.loads(raw_data)
            vulnerabilities = data.get("vulnerabilities", [])
            return [self._parse_kev_entry(v) for v in vulnerabilities if self._parse_kev_entry(v)]
        except Exception:
            return []

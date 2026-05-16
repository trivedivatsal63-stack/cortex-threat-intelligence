"""
CVE processing pipeline - transforms raw CVE data into enriched
vulnerability intelligence with exploit context and prioritization.

Processing steps:
1. Validate CVE ID format
2. Deduplication
3. Severity classification
4. AI enrichment (for high/critical CVEs)
5. Exploit availability tracking
6. Vendor/product extraction

WHY THIS EXISTS: Raw CVE data from NVD lacks prioritization context.
This processor adds exploit intelligence, AI analysis, and risk scoring
to help security teams focus on the most critical vulnerabilities first.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from config.settings import config
from utils.dedup import compute_cve_hash, global_dedup
from ai_engine.groq_client import groq_client
from utils.normalizer import sanitize_input


class CVEProcessor:
    """
    Processes raw CVE data through enrichment pipeline.
    
    Features:
    - Severity-based prioritization for AI processing
    - Only high/critical CVEs get AI analysis (saves API costs)
    - Exploit availability tracking
    - CISA KEV cross-referencing
    """
    
    def __init__(self):
        self.processed_count = 0
        self.ai_processed_count = 0
    
    def process(self, raw_cves: List[Dict]) -> List[Dict]:
        """
        Process raw CVE data into enriched vulnerability intelligence.
        """
        if not raw_cves:
            return []
        
        logger.info(f"Processing {len(raw_cves)} CVEs...")
        
        processed = []
        for cve in raw_cves:
            try:
                result = self._process_single(cve)
                if result:
                    processed.append(result)
            except Exception as e:
                logger.warning(f"CVE processing error: {e}")
                continue
        
        # AI enrichment for high/critical CVEs
        processed = self._run_ai_enrichment(processed)
        
        logger.info(
            f"CVE processing complete: {len(processed)} CVEs "
            f"({self.ai_processed_count} AI-enriched)"
        )
        
        return processed
    
    def _process_single(self, cve: Dict) -> Optional[Dict]:
        """Process a single CVE entry."""
        cve_id = cve.get("cve_id", "").strip()
        if not cve_id or not cve_id.startswith("CVE-"):
            return None
        
        # Dedup
        cve_hash = cve.get("cve_hash", "") or compute_cve_hash(cve_id)
        if global_dedup.check_and_mark(cve_hash):
            return None
        
        # Determine severity from CVSS or AI
        severity = cve.get("severity", "")
        if not severity:
            cvss_v3 = cve.get("cvss_v3_score")
            if cvss_v3 is not None:
                if cvss_v3 >= 9.0:
                    severity = "CRITICAL"
                elif cvss_v3 >= 7.0:
                    severity = "HIGH"
                elif cvss_v3 >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "UNKNOWN"
        
        description = sanitize_input(cve.get("description", ""))
        
        processed = {
            "cve_id": cve_id,
            "cve_hash": cve_hash,
            "description": description[:5000],
            "cvss_v2_score": cve.get("cvss_v2_score"),
            "cvss_v3_score": cve.get("cvss_v3_score"),
            "severity": severity,
            "exploit_available": cve.get("exploit_available", False),
            "exploit_references": cve.get("exploit_references", []),
            "affected_vendors": cve.get("affected_vendors", []),
            "affected_products": cve.get("affected_products", []),
            "attack_vector": cve.get("attack_vector"),
            "published_date": cve.get("published_date"),
            "last_modified": cve.get("last_modified"),
            "mitre_techniques": cve.get("mitre_techniques", []),
            "mitre_tactics": cve.get("mitre_tactics", []),
            "ai_summary": None,
            "ai_classification": None,
            "ai_processed": cve.get("ai_processed", False),
            "ai_processed_at": cve.get("ai_processed_at"),
            "metadata": {
                "source_type": cve.get("metadata", {}).get("source_type", "nvd"),
                "cisa_kev": cve.get("source_type") == "cisa_kev",
            },
        }
        
        # CISA KEV entries are always critical and exploited
        if cve.get("source_type") == "cisa_kev":
            processed["severity"] = "CRITICAL"
            processed["exploit_available"] = True
            processed["metadata"]["cisa_kev"] = True
            processed["metadata"]["cisa_required_action"] = cve.get("required_action")
            processed["metadata"]["cisa_due_date"] = cve.get("due_date")
        
        return processed
    
    def _run_ai_enrichment(self, cves: List[Dict]) -> List[Dict]:
        """
        AI enrichment for important CVEs — limited to 5 per run.
        
        Priority:
        1. CISA KEV entries (actively exploited in the wild)
        2. CRITICAL severity CVEs
        3. CVEs with known exploits

        WHY: Groq free tier has rate limits (30 RPM / 12K TPM).
        We process max 5 CVEs per run to stay within limits.
        Already-seen CVEs are skipped via content_hash dedup.
        """
        processed = 0
        max_per_run = 5
        
        # Sort: CISA KEV first, then CRITICAL, then HIGH with exploits
        priority_cves = sorted(cves, key=lambda c: (
            0 if c.get("metadata", {}).get("cisa_kev") else
            1 if c.get("severity") == "CRITICAL" else
            2 if c.get("severity") == "HIGH" and c.get("exploit_available") else
            3
        ))
        
        for cve in priority_cves:
            if cve.get("ai_processed"):
                continue
            if processed >= max_per_run:
                break
            
            severity = cve.get("severity", "LOW")
            if severity not in ("CRITICAL", "HIGH"):
                continue
            
            ai_result = groq_client.analyze_cve(
                cve["cve_id"],
                cve.get("description", ""),
                cve.get("cvss_v3_score") or cve.get("cvss_v2_score"),
            )
            
            if ai_result:
                cve["ai_summary"] = ai_result.get("summary")
                cve["ai_classification"] = ai_result.get("classification")
                cve["ai_processed"] = True
                cve["ai_processed_at"] = datetime.now(timezone.utc).isoformat()
                cve["metadata"]["exploit_maturity"] = ai_result.get("exploit_maturity")
                cve["metadata"]["patch_priority"] = ai_result.get("patch_priority")
                cve["metadata"]["ai_recommendation"] = ai_result.get("recommendation")
                cve["mitre_techniques"] = ai_result.get("mitre_attack_techniques", [])
                self.ai_processed_count += 1
                processed += 1
                logger.info(f"AI analyzed CVE {cve['cve_id']} ({processed}/{max_per_run})")
        
        return cves

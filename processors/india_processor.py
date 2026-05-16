"""
India-specific threat intelligence processor.
Processes alerts and scam reports from Indian sources.

WHY THIS EXISTS: Indian cyber threats have unique characteristics
(UPI fraud, Aadhaar scams, etc.) that need specialized processing
beyond what the general processors provide.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from utils.dedup import compute_article_hash, global_dedup
from utils.normalizer import sanitize_input, extract_india_keywords
from config.sources import INDIA_SCAM_KEYWORDS, INDIAN_BANKS, UPI_APPS
from ai_engine.groq_client import groq_client


class IndiaProcessor:
    """
    Processes India-specific cyber threat data.
    
    Handles:
    - CERT-In advisories
    - Indian cybercrime reports
    - UPI fraud/scam data
    - Indian banking threats
    - I4C (Indian Cyber Crime Coordination Centre) data
    """
    
    def __init__(self):
        self.processed_count = 0
        self.ai_processed_count = 0
    
    def process_alerts(self, raw_alerts: List[Dict]) -> List[Dict]:
        """Process India-specific cyber alerts."""
        if not raw_alerts:
            return []
        
        logger.info(f"Processing {len(raw_alerts)} India alerts...")
        
        processed = []
        for alert in raw_alerts:
            try:
                result = self._process_alert(alert)
                if result:
                    processed.append(result)
            except Exception as e:
                logger.warning(f"India alert processing error: {e}")
                continue
        
        logger.info(f"India alerts processed: {len(processed)}")
        return processed
    
    def process_scams(self, raw_scams: List[Dict]) -> List[Dict]:
        """Process Indian scam campaign data."""
        if not raw_scams:
            return []
        
        logger.info(f"Processing {len(raw_scams)} India scam reports...")
        
        processed = []
        for scam in raw_scams:
            try:
                result = self._process_scam(scam)
                if result:
                    processed.append(result)
            except Exception as e:
                logger.warning(f"India scam processing error: {e}")
                continue
        
        logger.info(f"India scams processed: {len(processed)}")
        return processed
    
    def _process_alert(self, alert: Dict) -> Optional[Dict]:
        """Process a single India cyber alert."""
        title = sanitize_input(alert.get("title", ""))
        if not title:
            return None
        
        content_hash = alert.get("content_hash", "")
        if not content_hash:
            content_hash = compute_article_hash(
                title, alert.get("url", ""), alert.get("published_date")
            )
        
        if global_dedup.check_and_mark(content_hash):
            return None
        
        processed = {
            "title": title,
            "url": alert.get("url", ""),
            "source": alert.get("source", "Unknown"),
            "alert_type": alert.get("alert_type", "general"),
            "description": sanitize_input(alert.get("description", ""))[:5000],
            "severity": alert.get("severity", "MEDIUM"),
            "affected_sectors": alert.get("affected_sectors", []),
            "affected_states": alert.get("affected_states", []),
            "targeted_banks": alert.get("targeted_banks", []),
            "published_date": alert.get("published_date"),
            "scam_type": alert.get("scam_type"),
            "scam_amount": alert.get("scam_amount"),
            "upi_apps": alert.get("upi_apps", []),
            "content_hash": content_hash,
            "ai_summary": None,
            "ai_classification": None,
            "ai_processed": False,
            "ai_processed_at": None,
        }
        
        # AI enrichment for important alerts
        severity = alert.get("severity", "MEDIUM")
        if severity in ("CRITICAL", "HIGH"):
            ai_result = self._run_ai_analysis(processed)
            if ai_result:
                processed.update(ai_result)
                self.ai_processed_count += 1
        
        self.processed_count += 1
        return processed
    
    def _process_scam(self, scam: Dict) -> Optional[Dict]:
        """Process a single Indian scam campaign entry."""
        title = sanitize_input(scam.get("title", ""))
        if not title:
            return None
        
        content_hash = scam.get("content_hash", "")
        if not content_hash:
            text = f"{title}|{scam.get('scam_type', '')}|{scam.get('description', '')}"
            content_hash = compute_article_hash(title, text)
        
        if global_dedup.check_and_mark(content_hash):
            return None
        
        return {
            "scam_name": title,
            "scam_type": scam.get("scam_type", "unknown"),
            "description": sanitize_input(scam.get("description", ""))[:3000],
            "platform": scam.get("upi_apps", scam.get("platform", [])),
            "targeted_banks": scam.get("targeted_banks", []),
            "targeted_regions": scam.get("affected_states", []),
            "reported_amount": scam.get("scam_amount"),
            "indicators": [],
            "first_reported": scam.get("published_date"),
            "last_reported": datetime.now(timezone.utc).isoformat(),
            "incidents_count": 1,
            "is_active": True,
            "content_hash": content_hash,
            "ai_summary": None,
            "ai_processed": False,
        }
    
    def _run_ai_analysis(self, alert: Dict) -> Optional[Dict]:
        """Run AI analysis on India threat data."""
        ai_result = groq_client.detect_india_threat(
            alert["title"],
            alert.get("description", "")[:4000],
        )
        
        if ai_result:
            return {
                "ai_summary": ai_result.get("ai_summary"),
                "ai_classification": ai_result.get("india_threat_type", alert.get("scam_type")),
                "ai_processed": True,
                "ai_processed_at": datetime.now(timezone.utc).isoformat(),
            }
        
        return None

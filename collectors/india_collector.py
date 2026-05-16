"""
India-specific cyber threat intelligence collector.
Collects from Indian cybersecurity sources and identifies
India-relevant threats in global data.

WHY THIS EXISTS: India faces unique cyber threats (UPI fraud, Aadhaar scams,
SIM swap attacks, fake KYC, etc.) that global feeds may not adequately cover.
This module provides focused collection from Indian sources and enriches
global data with India-specific threat detection.
"""

import asyncio
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from loguru import logger
from bs4 import BeautifulSoup

from collectors.base import BaseCollector
from collectors.rss_collector import RSSCollector
from config.sources import INDIA_SOURCES, INDIA_SCAM_KEYWORDS, INDIAN_BANKS, UPI_APPS
from config.settings import config
from utils.dedup import compute_article_hash, compute_content_hash
from utils.normalizer import clean_html, parse_date, extract_india_keywords


class IndiaThreatCollector:
    """
    Orchestrates India-specific threat intelligence collection.
    Uses RSS collectors for Indian sources and keyword matching
    on global data for India-relevant threats.
    """
    
    def __init__(self):
        self.collectors = []
        for source in INDIA_SOURCES:
            self.collectors.append(RSSCollector(source))
    
    async def collect_all(self) -> Dict[str, List[Dict]]:
        """
        Collect from all Indian sources.
        Returns categorized results.
        """
        results = {
            "articles": [],
            "alerts": [],
            "scams": [],
        }
        
        # Collect from all configured Indian sources concurrently
        tasks = [collector.collect() for collector in self.collectors]
        collections = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, collection in enumerate(collections):
            if isinstance(collection, Exception):
                logger.error(
                    f"India collector {INDIA_SOURCES[i].name} failed: {collection}"
                )
                continue
            
            source_name = INDIA_SOURCES[i].name
            for item in collection:
                # Enrich with India-specific metadata
                enriched = self._enrich_india_item(item, source_name)
                if enriched.get("alert_type"):
                    results["alerts"].append(enriched)
                elif enriched.get("scam_type"):
                    results["scams"].append(enriched)
                else:
                    results["articles"].append(enriched)
        
        logger.info(
            f"India collection: {len(results['articles'])} articles, "
            f"{len(results['alerts'])} alerts, {len(results['scams'])} scams"
        )
        return results
    
    def _enrich_india_item(self, item: Dict, source_name: str) -> Dict:
        """
        Enrich an item with India-specific metadata.
        Detects scam types, targeted banks, UPI references, etc.
        """
        text = f"{item.get('title', '')} {item.get('cleaned_content', '')}".lower()
        
        # Determine alert type by source
        alert_type = None
        if "cert-in" in source_name.lower():
            alert_type = "cert-in"
        elif "rbi" in source_name.lower():
            alert_type = "rbi"
        elif "dsci" in source_name.lower():
            alert_type = "dsci"
        elif "meity" in source_name.lower() or "ministry" in text:
            alert_type = "meity"
        
        # Detect scam types
        scam_type = self._detect_scam_type(text)
        
        # Detect targeted banks
        targeted_banks = [
            bank for bank in INDIAN_BANKS 
            if bank.lower() in text
        ]
        
        # Detect UPI apps mentioned
        upi_mentions = [
            app for app in UPI_APPS 
            if app.lower() in text
        ]
        
        # Detect affected states/regions (Indian states)
        indian_states = [
            "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
            "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand",
            "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
            "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab",
            "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
            "Uttar Pradesh", "Uttarakhand", "West Bengal",
            "Delhi", "Mumbai", "Bengaluru", "Chennai", "Hyderabad", "Kolkata",
        ]
        affected_states = [
            state for state in indian_states 
            if state.lower() in text
        ]
        
        # Try to extract scam amounts (Indian Rupees)
        amount_pattern = r'(?:rs\.?\s*|₹\s*|inr\s*|rupees?\s*)(\d[\d,]*\d(?:\s*(?:crore|lakh|thousand|million|billion))?)'
        amounts = re.findall(amount_pattern, text, re.IGNORECASE)
        
        item.update({
            "is_india_related": True,
            "alert_type": alert_type,
            "scam_type": scam_type,
            "targeted_banks": targeted_banks if targeted_banks else None,
            "upi_apps": upi_mentions if upi_mentions else None,
            "affected_states": affected_states if affected_states else None,
            "scam_amount": amounts[0] if amounts else None,
            "india_keywords": extract_india_keywords(text, INDIA_SCAM_KEYWORDS),
        })
        
        return item
    
    def _detect_scam_type(self, text: str) -> Optional[str]:
        """Detect the type of Indian scam based on keywords."""
        scam_patterns = {
            "upi-fraud": ["upi", "upi fraud", "gpay", "phonepe", "paytm", "upi scam"],
            "fake-kyc": ["kyc", "kyc scam", "kyc fraud", "fake kyc"],
            "sim-swap": ["sim swap", "sim swapping", "sim card fraud"],
            "aadhaar-scam": ["aadhaar", "aadhaar leak", "aadhaar scam"],
            "trading-app-scam": ["trading app", "trading scam", "fake trading", "investment scam"],
            "loan-app-scam": ["loan app", "instant loan", "loan scam"],
            "whatsapp-scam": ["whatsapp", "whatsapp scam", "whatsapp fraud"],
            "banking-fraud": ["bank fraud", "internet banking", "net banking fraud"],
            "phishing-india": ["phishing india", "indian phishing", "fake domain"],
            "crypto-scam": ["crypto", "bitcoin", "cryptocurrency scam"],
            "olx-scam": ["olx", "olx fraud", "olx scam"],
            "job-scam": ["job scam", "fake job", "employment fraud"],
        }
        
        for scam_type, keywords in scam_patterns.items():
            for keyword in keywords:
                if keyword in text:
                    return scam_type
        
        return None
    
    def check_global_item(self, item: Dict) -> Dict:
        """
        Check if a global item (from non-Indian sources) is relevant to India.
        Used to enrich global articles with India context.
        """
        text = f"{item.get('title', '')} {item.get('cleaned_content', '')}".lower()
        
        matched_keywords = extract_india_keywords(text, INDIA_SCAM_KEYWORDS)
        if matched_keywords:
            item["is_india_related"] = True
            item["india_keywords"] = matched_keywords
            item["scam_type"] = self._detect_scam_type(text)
            
            targeted_banks = [
                bank for bank in INDIAN_BANKS 
                if bank.lower() in text
            ]
            if targeted_banks:
                item["targeted_banks"] = targeted_banks
        
        return item

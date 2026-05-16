"""
Orchestrator that manages all data collection across ALL sources.
Runs collectors concurrently for maximum efficiency and aggregates results.

WHY THIS EXISTS: Running all collectors individually would be complex and
inefficient. This orchestrator coordinates the entire collection pipeline:
- Runs global + India collectors concurrently
- Aggregates and categorizes results
- Handles failures gracefully (one failing collector doesn't break others)
- Provides unified collection statistics
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from config.sources import GLOBAL_SOURCES, INDIA_SOURCES
from collectors.rss_collector import RSSCollector
from collectors.nvd_collector import NVDCollector
from collectors.cisa_collector import CISACollector
from collectors.api_collector import APICollector
from collectors.india_collector import IndiaThreatCollector


class CollectionOrchestrator:
    """
    Coordinates all data collection activities.
    """
    
    def __init__(self):
        self.global_collectors = self._build_global_collectors()
        self.india_collector = IndiaThreatCollector()
        self.stats = {
            "total_collected": 0,
            "sources_succeeded": 0,
            "sources_failed": 0,
            "started_at": None,
            "completed_at": None,
        }
    
    def _build_global_collectors(self) -> List:
        """Build collector instances for all global sources based on their type."""
        collectors = []
        for source in GLOBAL_SOURCES:
            if not source.enabled:
                continue
            
            collector = self._create_collector(source)
            if collector:
                collectors.append(collector)
        
        logger.info(f"Built {len(collectors)} global collectors")
        return collectors
    
    def _create_collector(self, source):
        """
        Create the appropriate collector type for each source.
        
        WHY: Different sources require different collection strategies.
        RSS sources need XML parsing, NVD needs API pagination,
        CISA needs JSON processing, etc.
        """
        try:
            if source.source_type == "rss":
                return RSSCollector(source)
            elif source.name == "NVD CVE API":
                return NVDCollector(source)
            elif "CISA" in source.name:
                return CISACollector(source)
            elif source.source_type == "api":
                return APICollector(source)
            else:
                logger.warning(f"No collector for source type: {source.source_type} ({source.name})")
                return None
        except Exception as e:
            logger.error(f"Failed to create collector for {source.name}: {e}")
            return None
    
    async def collect_all(self) -> Dict[str, List[Dict]]:
        """
        Run ALL collectors and aggregate results.
        
        Returns categorized results:
        - articles: Cybersecurity news articles
        - cves: CVE vulnerability data from NVD
        - iocs: Indicators of Compromise
        - india: India-specific intelligence
        """
        self.stats["started_at"] = datetime.now(timezone.utc)
        logger.info("=== Starting global data collection ===")
        
        results = {
            "articles": [],
            "cves": [],
            "iocs": [],
            "india_articles": [],
            "india_alerts": [],
            "india_scams": [],
        }
        
        # 1. Collect from global sources concurrently
        tasks = [self._safe_collect(c) for c in self.global_collectors]
        global_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 2. Collect from Indian sources
        india_results = await self._safe_collect_india()
        
        # 3. Categorize all results
        for collector_result in global_results:
            if isinstance(collector_result, list):
                for item in collector_result:
                    self._categorize_item(item, results)
        
        # 4. Enrich global items with India detection
        enriched_india_count = 0
        for article in results["articles"]:
            enriched = self.india_collector.check_global_item(article)
            if enriched.get("is_india_related"):
                enriched_india_count += 1
        
        # 5. Add India-specific results
        if india_results:
            results["india_articles"].extend(india_results.get("articles", []))
            results["india_alerts"].extend(india_results.get("alerts", []))
            results["india_scams"].extend(india_results.get("scams", []))
        
        # Track stats
        self.stats["total_collected"] = sum(len(v) for v in results.values())
        self.stats["completed_at"] = datetime.now(timezone.utc)
        
        duration = (self.stats["completed_at"] - self.stats["started_at"]).total_seconds()
        
        logger.info(
            f"=== Collection complete: {self.stats['total_collected']} items in {duration:.1f}s ===\n"
            f"  Articles: {len(results['articles'])} (+ {enriched_india_count} India-relevant)\n"
            f"  CVEs: {len(results['cves'])}\n"
            f"  IOCs: {len(results['iocs'])}\n"
            f"  India articles: {len(results['india_articles'])}\n"
            f"  India alerts: {len(results['india_alerts'])}\n"
            f"  India scams: {len(results['india_scams'])}"
        )
        
        return results
    
    async def _safe_collect(self, collector) -> List[Dict]:
        """Safely run a collector, catching and logging any errors."""
        try:
            logger.info(f"Collecting from: {collector.source.name}")
            items = await collector.collect()
            self.stats["sources_succeeded"] += 1
            return items
        except Exception as e:
            logger.error(f"Collector {collector.source.name} failed: {e}")
            self.stats["sources_failed"] += 1
            return []
    
    async def _safe_collect_india(self) -> Dict:
        """Safely run India-specific collection."""
        try:
            logger.info("Collecting from Indian sources...")
            return await self.india_collector.collect_all()
        except Exception as e:
            logger.error(f"India collection failed: {e}")
            return {"articles": [], "alerts": [], "scams": []}
    
    def _categorize_item(self, item: Dict, results: Dict) -> None:
        """Route each collected item to the appropriate category."""
        if "cve_id" in item:
            results["cves"].append(item)
        elif "ioc_value" in item:
            results["iocs"].append(item)
        else:
            results["articles"].append(item)
    
    def get_statistics(self) -> Dict:
        """Get collection run statistics."""
        return self.stats

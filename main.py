"""
Cyber Threat Intelligence Platform - Main Orchestration Pipeline.
Entry point for all data collection, processing, and reporting operations.

WHY THIS EXISTS: This is the central nervous system of the platform.
It coordinates the entire pipeline: collect -> process -> store -> analyze -> report -> alert.
Each phase can run independently for modularity and debugging.
"""

import os
import sys
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loguru import logger

from config.settings import config
from utils.logging import setup_logging
from utils.dedup import global_dedup

from collectors.orchestrator import CollectionOrchestrator
from processors.article_processor import ArticleProcessor
from processors.cve_processor import CVEProcessor
from processors.ioc_processor import IOCProcessor
from processors.india_processor import IndiaProcessor
from ai_engine.groq_client import groq_client
from database.connection import db as database
from database.supabase_client import supabase
from reports.generator import ReportGenerator
from alerts.alert_manager import alert_manager
from alerts.telegram_bot import telegram_bot


class ThreatIntelPipeline:
    """
    Main pipeline orchestrating the complete threat intelligence workflow.
    
    Pipeline stages:
    1. COLLECT - Gather data from all sources
    2. PROCESS - Clean, normalize, and extract intelligence
    3. AI ENRICH - Apply AI analysis (summarization, classification)
    4. STORE - Save to database with deduplication
    5. REPORT - Generate intelligence reports
    6. ALERT - Send notifications for critical threats
    
    Each stage is independent - if one fails, the pipeline continues.
    """
    
    def __init__(self):
        self.collector = CollectionOrchestrator()
        self.article_processor = ArticleProcessor()
        self.cve_processor = CVEProcessor()
        self.ioc_processor = IOCProcessor()
        self.india_processor = IndiaProcessor()
        self.report_generator = ReportGenerator()
        
        self.start_time = None
        self.stats = {
            "articles_collected": 0,
            "articles_processed": 0,
            "cves_collected": 0,
            "cves_processed": 0,
            "iocs_extracted": 0,
            "india_alerts": 0,
            "ai_processed": 0,
            "alerts_sent": 0,
            "reports_generated": 0,
        }
    
    async def run_full_pipeline(self) -> Dict[str, Any]:
        """
        Run the complete intelligence pipeline from collection to alerting.
        This is the primary entry point for scheduled runs.
        """
        self.start_time = datetime.now(timezone.utc)
        logger.info("=" * 60)
        logger.info("🚀 CYBER THREAT INTELLIGENCE PIPELINE STARTING")
        logger.info("=" * 60)
        
        results = {}
        
        # Stage 1: Collect
        results["collection"] = await self._run_collection()
        
        # Stage 2: Process
        results["processing"] = self._run_processing(results["collection"])
        
        # Stage 3: AI Enrichment
        results["ai"] = self._run_ai_enrichment(results["processing"])
        
        # Stage 4: Store
        results["storage"] = self._run_storage(results["processing"])
        
        # Stage 5: Generate Reports
        results["reports"] = self._run_reports(results["processing"])
        
        # Stage 6: Send Alerts
        results["alerts"] = self._run_alerts(results["processing"])
        
        # Print final summary
        self._print_summary()
        
        # Clear dedup tracker for next run
        global_dedup._seen.clear()
        
        return results
    
    async def run_collection_only(self) -> Dict[str, Any]:
        """Run only the data collection phase. Useful for debugging."""
        logger.info("Running collection-only mode...")
        return await self._run_collection()
    
    def run_processing_only(self, data: Dict) -> Dict[str, Any]:
        """Run only the processing phase on pre-collected data."""
        logger.info("Running processing-only mode...")
        return self._run_processing(data)
    
    def run_report_only(self, data: Dict) -> Dict[str, Any]:
        """Run only the report generation phase."""
        logger.info("Running report-only mode...")
        return self._run_reports(data)
    
    # ======================================================================
    # Pipeline Stages
    # ======================================================================
    
    async def _run_collection(self) -> Dict[str, Any]:
        """Stage 1: Collect data from all sources."""
        logger.info("📡 STAGE 1: DATA COLLECTION")
        
        try:
            raw_data = await self.collector.collect_all()
            
            self.stats["articles_collected"] = len(raw_data.get("articles", []))
            self.stats["cves_collected"] = len(raw_data.get("cves", []))
            self.stats["india_alerts"] = len(raw_data.get("india_alerts", []))
            
            logger.info(
                f"Collection complete: {self.stats['articles_collected']} articles, "
                f"{self.stats['cves_collected']} CVEs, "
                f"{self.stats['india_alerts']} India alerts"
            )
            
            return raw_data
        except Exception as e:
            logger.error(f"Collection stage failed: {e}")
            return {"articles": [], "cves": [], "iocs": [], 
                    "india_articles": [], "india_alerts": [], "india_scams": []}
    
    def _run_processing(self, raw_data: Dict) -> Dict[str, Any]:
        """Stage 2: Process and normalize collected data."""
        logger.info("⚙️ STAGE 2: DATA PROCESSING")
        
        processed = {
            "articles": [],
            "cves": [],
            "iocs": [],
            "india_alerts": [],
            "india_scams": [],
        }
        
        # Process articles
        try:
            processed["articles"] = self.article_processor.process(
                raw_data.get("articles", []) + raw_data.get("india_articles", [])
            )
            self.stats["articles_processed"] = len(processed["articles"])
            logger.info(f"Articles processed: {len(processed['articles'])}")
        except Exception as e:
            logger.error(f"Article processing failed: {e}")
        
        # Process CVEs
        try:
            processed["cves"] = self.cve_processor.process(raw_data.get("cves", []))
            self.stats["cves_processed"] = len(processed["cves"])
            logger.info(f"CVEs processed: {len(processed['cves'])}")
        except Exception as e:
            logger.error(f"CVE processing failed: {e}")
        
        # Extract IOCs
        try:
            processed["iocs"] = self.ioc_processor.process(
                processed["articles"], processed["cves"]
            )
            self.stats["iocs_extracted"] = len(processed["iocs"])
            logger.info(f"IOCs extracted: {len(processed['iocs'])}")
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
        
        # Process India-specific data
        try:
            processed["india_alerts"] = self.india_processor.process_alerts(
                raw_data.get("india_alerts", [])
            )
            processed["india_scams"] = self.india_processor.process_scams(
                raw_data.get("india_scams", [])
            )
            logger.info(
                f"India data processed: {len(processed['india_alerts'])} alerts, "
                f"{len(processed['india_scams'])} scams"
            )
        except Exception as e:
            logger.error(f"India processing failed: {e}")
        
        return processed
    
    def _run_ai_enrichment(self, processed: Dict) -> Dict[str, Any]:
        """Stage 3: AI enrichment of processed data."""
        logger.info("🧠 STAGE 3: AI ENRICHMENT")
        
        ai_stats = {"articles_processed": 0, "cves_processed": 0, "india_processed": 0}
        
        ai_stats["articles_processed"] = self.article_processor.ai_processed_count
        ai_stats["cves_processed"] = self.cve_processor.ai_processed_count
        ai_stats["india_processed"] = self.india_processor.ai_processed_count
        
        self.stats["ai_processed"] = sum(ai_stats.values())
        logger.info(f"AI enrichment: {ai_stats}")
        
        return ai_stats
    
    def _run_storage(self, processed: Dict) -> Dict[str, int]:
        """Stage 4: Store processed data in database using batch upserts."""
        logger.info("💾 STAGE 4: DATABASE STORAGE")
        
        storage_stats = {"articles": 0, "cves": 0, "iocs": 0, "india_alerts": 0, "india_scams": 0}
        
        # Batch store each type (much faster than individual upserts)
        storage_stats["articles"] = supabase.batch_upsert("articles", processed.get("articles", []), on_conflict="content_hash")
        storage_stats["cves"] = supabase.batch_upsert("cves", processed.get("cves", []), on_conflict="cve_hash")
        storage_stats["iocs"] = supabase.batch_upsert("iocs", processed.get("iocs", []), on_conflict="ioc_hash")
        storage_stats["india_alerts"] = supabase.batch_upsert("india_cyber_alerts", processed.get("india_alerts", []), on_conflict="content_hash")
        storage_stats["india_scams"] = supabase.batch_upsert("india_scam_tracking", processed.get("india_scams", []), on_conflict="content_hash")
        
        logger.info(f"Storage complete: {storage_stats}")
        return storage_stats
    
    def _run_reports(self, processed: Dict) -> Dict[str, Any]:
        """Stage 5: Generate intelligence reports."""
        logger.info("📊 STAGE 5: REPORT GENERATION")
        
        report_results = {}
        
        try:
            # Collect stats for reports
            report_data = {
                "articles": processed.get("articles", []),
                "cves": processed.get("cves", []),
                "iocs": {"ips": [], "domains": [], "hashes": [], "urls": []},
                "india_alerts": processed.get("india_alerts", []),
                "india_scams": processed.get("india_scams", []),
                "threat_actors": list(set(
                    a.get("metadata", {}).get("threat_actors", [])[0] 
                    for a in processed.get("articles", []) 
                    if a.get("metadata", {}).get("threat_actors")
                )),
                "malware_families": list(set(
                    m for a in processed.get("articles", [])
                    for m in (a.get("metadata", {}).get("malware_families", []) or [])
                )),
                "attack_vectors": {},
                "critical_cves": [c for c in processed.get("cves", []) 
                                 if c.get("severity") == "CRITICAL"],
                "high_threats": [a for a in processed.get("articles", [])
                               if a.get("severity") in ("CRITICAL", "HIGH")],
                "sources": list(set(a.get("source") for a in processed.get("articles", []))),
            }
            
            # Generate daily report
            try:
                daily_report = self.report_generator.generate_daily_report(report_data)
                report_results["daily"] = daily_report
                self.stats["reports_generated"] += 1
            except Exception as e:
                logger.error(f"Daily report generation failed: {e}")
            
            # Generate India digest (if India data exists)
            if processed.get("india_alerts") or processed.get("india_scams"):
                try:
                    india_report = self.report_generator.generate_india_digest(report_data)
                    report_results["india"] = india_report
                    self.stats["reports_generated"] += 1
                except Exception as e:
                    logger.error(f"India report generation failed: {e}")
            
            logger.info(f"Reports generated: {self.stats['reports_generated']}")
            
        except Exception as e:
            logger.error(f"Report generation stage failed: {e}")
        
        return report_results
    
    def _run_alerts(self, processed: Dict) -> Dict[str, int]:
        """Stage 6: Send alerts for critical threats."""
        logger.info("📨 STAGE 6: ALERT DISPATCH")
        
        alert_results = {"telegram": 0, "email": 0}
        
        if not (telegram_bot.enabled or config.alerts.email_to):
            logger.info("Alerting not configured. Skipping alerts.")
            return alert_results
        
        try:
            india_data = {
                "alerts": processed.get("india_alerts", []),
                "scams": processed.get("india_scams", []),
            }
            
            summary = alert_manager.process_items(
                articles=processed.get("articles", []),
                cves=processed.get("cves", []),
                india_data=india_data,
            )
            
            alert_results["telegram"] = summary.get("telegram_alerts", 0)
            alert_results["email"] = summary.get("email_alerts", 0)
            self.stats["alerts_sent"] = alert_results["telegram"] + alert_results["email"]
            
            logger.info(f"Alerts sent: {alert_results}")
            
        except Exception as e:
            logger.error(f"Alert dispatch failed: {e}")
        
        return alert_results
    
    def _print_summary(self) -> None:
        """Print pipeline execution summary."""
        duration = datetime.now(timezone.utc) - self.start_time
        
        logger.info("=" * 60)
        logger.info("✅ PIPELINE COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Duration: {duration.total_seconds():.1f}s")
        logger.info(f"Articles: {self.stats['articles_collected']} collected → {self.stats['articles_processed']} stored")
        logger.info(f"CVEs: {self.stats['cves_collected']} collected → {self.stats['cves_processed']} stored")
        logger.info(f"IOCs: {self.stats['iocs_extracted']} extracted")
        logger.info(f"India Alerts: {self.stats['india_alerts']}")
        logger.info(f"AI Enriched: {self.stats['ai_processed']} items")
        logger.info(f"Alerts Sent: {self.stats['alerts_sent']}")
        logger.info(f"Reports Generated: {self.stats['reports_generated']}")
        logger.info("=" * 60)


# =============================================================================
# CLI Entry Points
# =============================================================================

async def main():
    """
    Main entry point. Sets up logging and runs the pipeline.
    
    Command line arguments:
    --collect-only: Only run data collection
    --process-only: Only run processing (requires pre-collected data file)
    --report-only: Only generate reports
    --skip-alerts: Run pipeline without sending alerts
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence Platform")
    parser.add_argument("--collect-only", action="store_true", help="Only run data collection")
    parser.add_argument("--process-only", action="store_true", help="Only run processing")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--skip-alerts", action="store_true", help="Skip alert dispatch")
    parser.add_argument("--input-file", type=str, help="Input JSON file for process-only mode")
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    
    # Initialize database
    database.initialize()
    supabase.initialize()
    
    pipeline = ThreatIntelPipeline()
    
    if args.collect_only:
        await pipeline.run_collection_only()
    elif args.process_only:
        if args.input_file:
            import json
            with open(args.input_file, "r") as f:
                data = json.load(f)
            pipeline.run_processing_only(data)
        else:
            logger.error("--input-file required for --process-only mode")
    elif args.report_only:
        pipeline.run_report_only({})
    else:
        results = await pipeline.run_full_pipeline()
    
    logger.info("Pipeline execution finished.")


def run_cli():
    """CLI entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())

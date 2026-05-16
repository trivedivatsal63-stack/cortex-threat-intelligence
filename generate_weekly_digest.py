"""
Weekly Digest Generator - standalone script for generating weekly intelligence digests.
Run by GitHub Actions weekly workflow.

WHY THIS EXISTS: The weekly digest needs data from the entire week,
not just the current run. This script aggregates historical data from
the database to create comprehensive weekly reports.
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loguru import logger
from config.settings import config
from utils.logging import setup_logging
from database.supabase_client import supabase
from database.connection import db
from reports.generator import ReportGenerator
from ai_engine.groq_client import groq_client


def generate_weekly_digest():
    """Generate and save the weekly intelligence digest."""
    setup_logging()
    logger.info("Generating Weekly Intelligence Digest...")
    
    # Initialize
    db.initialize()
    supabase.initialize()
    report_gen = ReportGenerator()
    
    # Fetch data from the past week
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    
    articles = supabase.select("articles", limit=500)
    cves = supabase.select("cves", limit=500)
    india_alerts = supabase.select("india_cyber_alerts", limit=100)
    india_scams = supabase.select("india_scam_tracking", limit=100)
    
    logger.info(f"Loaded: {len(articles)} articles, {len(cves)} CVEs")
    
    # Build report data
    report_data = {
        "articles": articles,
        "cves": cves,
        "critical_cves": [c for c in cves if c.get("severity") == "CRITICAL"],
        "high_threats": [a for a in articles if a.get("severity") in ("CRITICAL", "HIGH")],
        "india_alerts": india_alerts,
        "india_scams": india_scams,
        "malware_families": [m for a in articles for m in (a.get("metadata", {}).get("malware_families", []) or [])],
        "threat_actors": [t for a in articles for t in (a.get("metadata", {}).get("threat_actors", []) or [])],
        "sectors": [s for a in articles for s in (a.get("metadata", {}).get("targeted_sectors", []) or [])],
        "attack_vectors": {},
        "sources": list(set(a.get("source", "") for a in articles)),
        "cert_in_alerts": [a for a in india_alerts if a.get("alert_type") == "cert-in"],
    }
    
    # Generate the digest
    result = report_gen.generate_weekly_digest(report_data)
    
    logger.info(f"Weekly digest saved to: {result.get('markdown', 'N/A')}")
    return result


if __name__ == "__main__":
    generate_weekly_digest()

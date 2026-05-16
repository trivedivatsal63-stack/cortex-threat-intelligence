"""
FastAPI REST API Server for the Cyber Threat Intelligence Platform.
Provides programmatic access to collected intelligence data.

WHY THIS EXISTS: A REST API enables integration with other tools
(SIEMs, dashboards, chatbots) and allows external systems to query
the threat intelligence database programmatically.
"""

from typing import List, Optional, Dict
from datetime import datetime, date
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger

from database.connection import db
from database.supabase_client import supabase
from config.settings import config


# =============================================================================
# API Models
# =============================================================================

class ArticleResponse(BaseModel):
    id: str
    title: str
    url: str
    source: str
    published_date: Optional[str] = None
    summary: Optional[str] = None
    threat_category: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    cve_ids: Optional[List[str]] = None
    is_india_related: bool = False
    created_at: str


class CVEResponse(BaseModel):
    id: str
    cve_id: str
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    exploit_available: bool = False
    affected_vendors: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    published_date: Optional[str] = None
    created_at: str


class IOCResponse(BaseModel):
    id: str
    ioc_value: str
    ioc_type: str
    threat_type: Optional[str] = None
    source: Optional[str] = None
    first_seen: str
    is_active: bool


class StatsResponse(BaseModel):
    total_articles: int
    total_cves: int
    total_iocs: int
    critical_cves: int
    india_alerts: int
    active_scams: int
    last_updated: str


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Cyber Threat Intelligence API",
    description="REST API for querying cybersecurity threat intelligence data collected from global and Indian sources.",
    version="1.0.0",
)

# CORS - allow dashboard and external tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health & Status Endpoints
# =============================================================================

@app.get("/health")
async def health_check():
    """API health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db.is_connected,
    }


@app.get("/stats", response_model=StatsResponse)
async def get_statistics():
    """Get overall platform statistics."""
    try:
        stats = {
            "total_articles": len(supabase.select("articles", limit=1000)),
            "total_cves": len(supabase.select("cves", limit=1000)),
            "total_iocs": len(supabase.select("iocs", limit=1000)),
            "critical_cves": len(supabase.select("cves", filters={"severity": "CRITICAL"})),
            "india_alerts": len(supabase.select("india_cyber_alerts")),
            "active_scams": len(supabase.select("india_scam_tracking", filters={"is_active": True})),
            "last_updated": datetime.utcnow().isoformat(),
        }
        return stats
    except Exception as e:
        logger.error(f"Stats endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")


# =============================================================================
# Articles Endpoints
# =============================================================================

@app.get("/articles", response_model=List[ArticleResponse])
async def get_articles(
    limit: int = Query(20, ge=1, le=100),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    india_only: bool = False,
    search: Optional[str] = None,
):
    """Get cybersecurity articles with optional filters."""
    try:
        filters = {}
        if source:
            filters["source"] = source
        if severity:
            filters["severity"] = severity
        if category:
            filters["threat_category"] = category
        if india_only:
            filters["is_india_related"] = True
        
        articles = supabase.select(
            "articles",
            filters=filters if filters else None,
            limit=limit,
            order_by="published_date",
        )
        return articles
    except Exception as e:
        logger.error(f"Articles endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch articles")


@app.get("/articles/{article_id}", response_model=ArticleResponse)
async def get_article(article_id: str):
    """Get a specific article by ID."""
    try:
        articles = supabase.select("articles", filters={"id": article_id}, limit=1)
        if not articles:
            raise HTTPException(status_code=404, detail="Article not found")
        return articles[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Article detail error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch article")


# =============================================================================
# CVEs Endpoints
# =============================================================================

@app.get("/cves", response_model=List[CVEResponse])
async def get_cves(
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    exploit_only: bool = False,
    vendor: Optional[str] = None,
):
    """Get CVE vulnerabilities with optional filters."""
    try:
        filters = {}
        if severity:
            filters["severity"] = severity
        
        cves = supabase.select(
            "cves",
            filters=filters if filters else None,
            limit=limit,
            order_by="published_date",
        )
        
        # Client-side filtering for special cases
        if exploit_only:
            cves = [c for c in cves if c.get("exploit_available")]
        if vendor:
            cves = [c for c in cves if vendor.lower() in " ".join(
                c.get("affected_vendors", []) or []).lower()]
        
        return cves
    except Exception as e:
        logger.error(f"CVEs endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch CVEs")


@app.get("/cves/{cve_id}", response_model=CVEResponse)
async def get_cve(cve_id: str):
    """Get a specific CVE by CVE ID (e.g., CVE-2024-12345)."""
    try:
        cves = supabase.select("cves", filters={"cve_id": cve_id.upper()}, limit=1)
        if not cves:
            raise HTTPException(status_code=404, detail="CVE not found")
        return cves[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE detail error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch CVE")


# =============================================================================
# IOCs Endpoints
# =============================================================================

@app.get("/iocs", response_model=List[IOCResponse])
async def get_iocs(
    limit: int = Query(20, ge=1, le=100),
    ioc_type: Optional[str] = None,
    threat_type: Optional[str] = None,
):
    """Get Indicators of Compromise with optional filters."""
    try:
        filters = {}
        if ioc_type:
            filters["ioc_type"] = ioc_type
        if threat_type:
            filters["threat_type"] = threat_type
        
        iocs = supabase.select(
            "iocs",
            filters=filters if filters else None,
            limit=limit,
            order_by="last_seen",
        )
        return iocs
    except Exception as e:
        logger.error(f"IOCs endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch IOCs")


# =============================================================================
# India-Specific Endpoints
# =============================================================================

@app.get("/india/alerts")
async def get_india_alerts(limit: int = Query(20, ge=1, le=100)):
    """Get India-specific cyber alerts."""
    try:
        alerts = supabase.select(
            "india_cyber_alerts",
            limit=limit,
            order_by="published_date",
        )
        return alerts
    except Exception as e:
        logger.error(f"India alerts endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch India alerts")


@app.get("/india/scams")
async def get_india_scams(limit: int = Query(20, ge=1, le=100), active_only: bool = True):
    """Get Indian scam tracking data."""
    try:
        filters = {"is_active": active_only} if active_only else None
        scams = supabase.select(
            "india_scam_tracking",
            filters=filters,
            limit=limit,
            order_by="last_reported",
        )
        return scams
    except Exception as e:
        logger.error(f"India scams endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch India scams")


# =============================================================================
# Reports Endpoints
# =============================================================================

@app.get("/reports")
async def get_reports(
    report_type: Optional[str] = None,
    limit: int = Query(10, ge=1, le=50),
):
    """Get generated intelligence reports."""
    try:
        filters = {}
        if report_type:
            filters["report_type"] = report_type
        
        reports = supabase.select(
            "reports",
            filters=filters if filters else None,
            limit=limit,
            order_by="report_date",
        )
        return reports
    except Exception as e:
        logger.error(f"Reports endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch reports")


# =============================================================================
# Search Endpoint
# =============================================================================

@app.get("/search")
async def search_intelligence(
    q: str = Query(..., min_length=2),
    limit: int = Query(10, ge=1, le=50),
):
    """Full-text search across articles and CVEs."""
    try:
        results = {"articles": [], "cves": [], "iocs": []}
        
        # Search articles
        try:
            articles = supabase.select("articles", limit=limit)
            results["articles"] = [
                a for a in articles 
                if q.lower() in (a.get("title", "") + " " + (a.get("cleaned_content") or "")).lower()
            ][:limit]
        except Exception:
            pass
        
        # Search CVEs
        try:
            cves = supabase.select("cves", limit=limit)
            results["cves"] = [
                c for c in cves 
                if q.lower() in c.get("cve_id", "").lower() 
                or q.lower() in (c.get("description") or "").lower()
            ][:limit]
        except Exception:
            pass
        
        return results
    except Exception as e:
        logger.error(f"Search endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Search failed")


# =============================================================================
# Startup & Shutdown
# =============================================================================

@app.on_event("startup")
async def startup():
    """Initialize database connections on startup."""
    logger.info("Starting Cyber Threat Intelligence API...")
    db.initialize()


@app.on_event("shutdown")
async def shutdown():
    """Clean up connections on shutdown."""
    logger.info("Shutting down Cyber Threat Intelligence API...")
    db.close()

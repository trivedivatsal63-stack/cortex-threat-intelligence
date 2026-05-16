"""
Data models (dataclasses) for structured data representation.
These models provide type-safe data transfer between modules.

WHY THIS EXISTS: Using dataclasses ensures type safety, makes code
more readable, and provides a contract between collectors, processors,
and the database layer.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class Article:
    """
    Represents a cybersecurity news article.
    Used by collectors to pass data to processors and database.
    """
    title: str
    url: str
    source: str
    content_hash: str
    author: Optional[str] = None
    published_date: Optional[datetime] = None
    article_content: Optional[str] = None
    cleaned_content: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[List[str]] = None
    cve_ids: Optional[List[str]] = None
    threat_category: Optional[str] = None
    severity: Optional[str] = None
    is_india_related: bool = False
    india_keywords: Optional[List[str]] = None
    ai_processed: bool = False
    ai_processed_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for database insertion."""
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
        return result


@dataclass
class CVE:
    """Represents a CVE vulnerability entry."""
    cve_id: str
    cve_hash: str
    description: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None
    severity: Optional[str] = None
    exploit_available: bool = False
    exploit_references: Optional[List[str]] = None
    affected_vendors: Optional[List[str]] = None
    affected_products: Optional[List[str]] = None
    attack_vector: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    mitre_techniques: Optional[List[str]] = None
    mitre_tactics: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    ai_classification: Optional[str] = None
    ai_processed: bool = False
    ai_processed_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
        return result


@dataclass
class IOC:
    """Represents an Indicator of Compromise."""
    ioc_value: str
    ioc_type: str  # ip, domain, md5, sha1, sha256, url
    ioc_hash: str
    threat_type: Optional[str] = None
    source: Optional[str] = None
    source_url: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[List[str]] = None
    confidence: float = 0.5
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
        return result


@dataclass
class IndiaCyberAlert:
    """India-specific cybersecurity alert."""
    title: str
    source: str
    content_hash: str
    url: Optional[str] = None
    alert_type: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    affected_sectors: Optional[List[str]] = None
    affected_states: Optional[List[str]] = None
    targeted_banks: Optional[List[str]] = None
    published_date: Optional[datetime] = None
    scam_type: Optional[str] = None
    scam_amount: Optional[str] = None
    upi_apps: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    ai_classification: Optional[str] = None
    ai_processed: bool = False
    ai_processed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
        return result


@dataclass
class Report:
    """Generated intelligence report."""
    report_type: str
    title: str
    report_date: str
    summary: Optional[str] = None
    content_markdown: Optional[str] = None
    content_html: Optional[str] = None
    content_json: Optional[Dict] = None
    stats: Optional[Dict] = None
    top_threats: Optional[List] = None
    critical_cves: Optional[List[str]] = None
    ransomware_mentions: int = 0
    phishing_mentions: int = 0
    india_incidents: int = 0
    metadata: Optional[Dict] = None

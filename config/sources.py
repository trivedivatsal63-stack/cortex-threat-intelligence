"""
Defines ALL data sources the platform collects from.
Organized by category for clarity and maintainability.
Each source has a name, type (api/rss/web), URL, and configuration.

WHY THIS EXISTS: Centralizing source definitions makes it easy to
add/remove/modify data sources without touching collection logic.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DataSource:
    """Represents a single data source configuration."""
    name: str
    source_type: str  # 'api', 'rss', 'web', 'json'
    url: str
    enabled: bool = True
    lookback_days: int = 7
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, str]] = None
    rate_limit: float = 1.0  # seconds between requests


# =============================================================================
# GLOBAL CYBERSECURITY SOURCES
# =============================================================================

GLOBAL_SOURCES: List[DataSource] = [
    # --- OFFICIAL CVE SOURCES ---
    DataSource(
        name="NVD CVE API",
        source_type="api",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        lookback_days=1,
        rate_limit=6.0,
        params={"noRejected": ""},
    ),
    DataSource(
        name="NVD CVE API (Alternative)",
        source_type="api",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        lookback_days=1,
        rate_limit=6.0,
    ),
    DataSource(
        name="CISA Known Exploited Vulnerabilities",
        source_type="api",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        lookback_days=30,
    ),
    DataSource(
        name="CISA Alerts",
        source_type="rss",
        url="https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
    ),
    DataSource(
        name="MITRE ATT&CK",
        source_type="api",
        url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        lookback_days=30,
    ),
    DataSource(
        name="GitHub Security Advisories",
        source_type="api",
        url="https://api.github.com/advisories",
        lookback_days=7,
        headers={"Accept": "application/vnd.github+json"},
    ),

    # --- CYBERSECURITY NEWS RSS ---
    DataSource(
        name="The Hacker News",
        source_type="rss",
        url="https://thehackernews.com/feeds/posts/default",
    ),
    DataSource(
        name="KrebsOnSecurity",
        source_type="rss",
        url="https://krebsonsecurity.com/feed/",
    ),
    DataSource(
        name="BleepingComputer",
        source_type="rss",
        url="https://www.bleepingcomputer.com/feed/",
    ),
    DataSource(
        name="Dark Reading",
        source_type="rss",
        url="https://www.darkreading.com/rss.xml",
    ),
    DataSource(
        name="SecurityWeek",
        source_type="rss",
        url="https://feeds.feedburner.com/Securityweek",
    ),
    DataSource(
        name="Malwarebytes Labs",
        source_type="rss",
        url="https://blog.malwarebytes.com/feed/",
    ),
    DataSource(
        name="Cisco Talos Blog",
        source_type="rss",
        url="https://feeds.feedburner.com/Talos",
    ),
    DataSource(
        name="Unit 42 Palo Alto",
        source_type="rss",
        url="https://unit42.paloaltonetworks.com/feed/",
    ),
    DataSource(
        name="CrowdStrike Blog",
        source_type="rss",
        url="https://www.crowdstrike.com/blog/feed/",
    ),
    DataSource(
        name="SentinelOne Blog",
        source_type="rss",
        url="https://www.sentinelone.com/blog/feed/",
    ),
    DataSource(
        name="Microsoft Security Blog",
        source_type="rss",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
    ),

    # --- THREAT INTELLIGENCE FEEDS ---
    DataSource(
        name="AlienVault OTX",
        source_type="api",
        url="https://otx.alienvault.com/api/v1/indicators/export",
        lookback_days=1,
        rate_limit=2.0,
    ),
    DataSource(
        name="AbuseIPDB",
        source_type="api",
        url="https://api.abuseipdb.com/api/v2/reports",
        lookback_days=1,
        rate_limit=2.0,
    ),
    DataSource(
        name="URLHaus",
        source_type="api",
        url="https://urlhaus-api.abuse.ch/v1/urls/recent/",
        lookback_days=1,
    ),
    DataSource(
        name="MalwareBazaar",
        source_type="api",
        url="https://mb-api.abuse.ch/api/v1/",
        lookback_days=1,
        rate_limit=2.0,
    ),
    DataSource(
        name="OpenPhish",
        source_type="api",
        url="https://openphish.com/feed.txt",
        lookback_days=1,
    ),
    DataSource(
        name="PhishTank",
        source_type="api",
        url="https://data.phishtank.com/data/online-valid.json",
        lookback_days=1,
    ),

    # --- EXPLOIT DATABASES ---
    DataSource(
        name="Exploit-DB RSS",
        source_type="rss",
        url="https://www.exploit-db.com/rss.xml",
    ),
    DataSource(
        name="Packet Storm Security",
        source_type="rss",
        url="https://rss.packetstormsecurity.com/",
    ),
]


# =============================================================================
# 🇮🇳 INDIA-SPECIFIC CYBERSECURITY SOURCES
# =============================================================================

INDIA_SOURCES: List[DataSource] = [
    DataSource(
        name="CERT-In Advisories",
        source_type="rss",
        url="https://www.cert-in.org.in/s2c-MainServlet?pageid=PDFRSS&rssid=CIVICAlerts",
    ),
    DataSource(
        name="CERT-In Alerts",
        source_type="web",
        url="https://www.cert-in.org.in/",
        lookback_days=7,
    ),
    DataSource(
        name="DSCI (Data Security Council of India)",
        source_type="rss",
        url="https://www.dsci.in/rss.xml",
    ),
    DataSource(
        name="Medianama Cybersecurity",
        source_type="rss",
        url="https://www.medianama.com/category/cybersecurity/feed/",
    ),
    DataSource(
        name="Indian Express Cybersecurity",
        source_type="rss",
        url="https://indianexpress.com/section/technology/cyber-security/feed/",
    ),
    DataSource(
        name="Times of India Cybercrime",
        source_type="rss",
        url="https://timesofindia.indiatimes.com/rssfeeds/66949542.cms",
    ),
    DataSource(
        name="The Hindu Cybersecurity",
        source_type="rss",
        url="https://www.thehindu.com/sci-tech/technology/internet/feed/",
    ),
]


# =============================================================================
# INDIAN SCAM/CYBERCRIME KEYWORDS FOR DETECTION
# =============================================================================

# Keywords used by the India module to detect relevant threats in global data
INDIA_SCAM_KEYWORDS: List[str] = [
    # UPI & Payments
    "UPI", "GPay", "PhonePe", "Paytm", "BHIM", "UPI fraud",
    # Aadhaar & Identity
    "Aadhaar", "Aadhaar scam", "Aadhaar leak", "Aadhaar data",
    # Banking
    "Indian bank", "SBI", "HDFC", "ICICI", "Axis Bank",
    "Yes Bank", "PNB", "Canara", "Indian banking", "RBI",
    # Scam types
    "KYC scam", "fake KYC", "SIM swap", "SIM swapping",
    "WhatsApp scam", "telecom scam", "Jio", "Airtel",
    "OLX scam", "loan app scam", "trading app scam",
    "fake trading", "investment scam", "crypto scam India",
    # Phishing
    "phishing India", "Indian phishing", "fake domain India",
    # Ransomware
    "ransomware India", "Indian healthcare ransomware",
    # CERT-In
    "CERT-In advisory", "CERT-In alert", "emergency advisory India",
    # Telecom
    "telecom fraud India", "SIM card fraud",
    # Government
    "MeitY", "cyber crime India", "cyber fraud India",
    "Indian cybercrime", "cybercrime portal",
]

# Indian banks frequently targeted
INDIAN_BANKS: List[str] = [
    "State Bank of India", "SBI", "HDFC Bank", "ICICI Bank",
    "Axis Bank", "Kotak Mahindra", "Yes Bank", "PNB",
    "Bank of Baroda", "Canara Bank", "Union Bank",
    "IDBI Bank", "Federal Bank", "IndusInd Bank",
]

# UPI app names
UPI_APPS: List[str] = [
    "GPay", "Google Pay", "PhonePe", "Paytm", "BHIM",
    "Amazon Pay", "CRED", "Mobikwik", "Freecharge",
]


# =============================================================================
# THREAT CATEGORIES & CLASSIFICATIONS
# =============================================================================

THREAT_CATEGORIES: Dict[str, str] = {
    "ransomware": "Malware that encrypts files and demands payment",
    "phishing": "Social engineering attacks to steal credentials",
    "malware": "General malicious software",
    "zero-day": "Previously unknown vulnerability being exploited",
    "supply-chain": "Attack targeting third-party dependencies",
    "cloud-attack": "Cloud infrastructure compromise",
    "insider-threat": "Threat from within the organization",
    "credential-theft": "Stealing login credentials",
    "apt": "Advanced Persistent Threat - sophisticated state-sponsored attack",
    "banking-fraud": "Financial fraud targeting banking systems",
    "telecom-scam": "Telecommunications fraud",
    "upi-fraud": "UPI (Indian payment system) fraud",
    "ddos": "Distributed Denial of Service attack",
    "iot-attack": "Internet of Things device compromise",
    "web-attack": "Web application attack (SQLi, XSS, etc.)",
    "data-breach": "Unauthorized data access/exfiltration",
    "social-engineering": "Psychological manipulation attacks",
}

# Priority mapping for AI processing
AI_PROCESSING_PRIORITY: Dict[str, int] = {
    "critical": 1,   # Critical CVEs, ransomware, Indian scams
    "high": 2,        # Exploits, active campaigns
    "medium": 3,      # General threat intelligence
    "low": 4,         # Generic news, repetitive articles
}

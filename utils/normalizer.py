"""
Text normalization utilities for cleaning and standardizing collected data.
Handles HTML cleaning, date parsing, and text standardization.

WHY THIS EXISTS: Raw collected data comes in many formats (HTML, XML, JSON).
This module normalizes everything into a consistent format for AI processing
and database storage.
"""

import re
import html
from datetime import datetime, timezone
from typing import Optional
from bs4 import BeautifulSoup
from loguru import logger


def clean_html(html_content: str) -> str:
    """
    Remove HTML tags, scripts, styles, and normalize whitespace.
    
    WHY: RSS feeds and web scraped content contain HTML that needs 
    to be stripped before AI processing to save tokens.
    """
    if not html_content:
        return ""
    
    # Parse with BeautifulSoup
    soup = BeautifulSoup(html_content, "html.parser")
    
    # Remove script and style elements
    for script in soup(["script", "style", "nav", "footer", "header"]):
        script.decompose()
    
    # Get text
    text = soup.get_text(separator=" ")
    
    # Unescape HTML entities
    text = html.unescape(text)
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\n\s*\n', '\n', text)
    
    return text.strip()


def truncate_text(text: str, max_length: int = 5000) -> str:
    """
    Truncate text to a maximum length while preserving word boundaries.
    Used to stay within AI token limits.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length].rsplit(' ', 1)[0] + "..."
    truncate_at = max_length
    if len(text) > truncate_at:
        return text[:truncate_at].rsplit(' ', 1)[0] + "..."
    return text


def parse_date(date_string: Optional[str]) -> Optional[datetime]:
    """
    Parse date strings from various formats into standardized datetime objects.
    Handles the many date formats used by different RSS feeds and APIs.
    
    Returns timezone-aware datetime in UTC.
    """
    if not date_string:
        return None
    
    # Common date format patterns
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%B %d, %Y",
        "%d %B %Y",
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(date_string.strip(), fmt)
            # Make timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            continue
    
    logger.warning(f"Could not parse date: {date_string}")
    return None


def extract_cve_ids(text: str) -> list:
    """
    Extract CVE IDs (e.g., CVE-2024-12345) from text.
    Uses regex pattern matching for standard CVE format.
    """
    if not text:
        return []
    pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_iocs(text: str) -> dict:
    """
    Extract Indicators of Compromise from text.
    Returns categorized dict of IPs, domains, hashes, URLs.
    """
    iocs = {
        "ips": [],
        "domains": [],
        "hashes": [],
        "urls": [],
    }
    
    if not text:
        return iocs
    
    # IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    iocs["ips"] = list(set(re.findall(ip_pattern, text)))
    
    # Domains (simple pattern)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    # Filter out common false positives
    domains = set(re.findall(domain_pattern, text))
    iocs["domains"] = [d for d in domains if not d.endswith(('.example.com', '.local', 'localhost'))]
    
    # Hashes (MD5, SHA1, SHA256)
    hash_patterns = [
        (r'\b[a-fA-F0-9]{32}\b', 'MD5'),
        (r'\b[a-fA-F0-9]{40}\b', 'SHA1'),
        (r'\b[a-fA-F0-9]{64}\b', 'SHA256'),
    ]
    for pattern, hash_type in hash_patterns:
        iocs["hashes"].extend([(h, hash_type) for h in re.findall(pattern, text)])
    iocs["hashes"] = list(set(iocs["hashes"]))
    
    # URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[-\w/?%&=+#]*'
    iocs["urls"] = list(set(re.findall(url_pattern, text)))
    
    return iocs


def extract_india_keywords(text: str, keywords: list) -> list:
    """
    Check if text contains India-specific keywords.
    Returns list of matched keywords for tagging.
    """
    if not text:
        return []
    text_lower = text.lower()
    matched = []
    for keyword in keywords:
        if keyword.lower() in text_lower:
            matched.append(keyword)
    return matched


def sanitize_input(text: str) -> str:
    """
    Sanitize text input to prevent injection attacks.
    Removes or escapes potentially dangerous characters.
    """
    if not text:
        return ""
    # Remove null bytes and control characters (except newlines and tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text.strip()

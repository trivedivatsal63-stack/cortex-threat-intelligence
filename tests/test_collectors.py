"""
Unit tests for data collectors.
Tests RSS parsing, API responses, and data normalization.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from collectors.rss_collector import RSSCollector
from collectors.nvd_collector import NVDCollector
from config.sources import DataSource


class TestRSSCollector:
    """Test RSS feed collection and parsing."""
    
    def setup_method(self):
        self.source = DataSource(
            name="Test RSS",
            source_type="rss",
            url="https://example.com/feed.xml",
        )
        self.collector = RSSCollector(self.source)
    
    def test_parse_valid_rss(self):
        """Test parsing a valid RSS XML response."""
        sample_rss = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>Test Feed</title>
                <item>
                    <title>Critical Vulnerability in System X</title>
                    <link>https://example.com/article1</link>
                    <description>New CVE-2024-12345 discovered affecting thousands</description>
                    <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
                    <author>Test Author</author>
                </item>
            </channel>
        </rss>"""
        
        results = self.collector.parse(sample_rss)
        assert len(results) == 1
        assert results[0]["title"] == "Critical Vulnerability in System X"
        assert results[0]["url"] == "https://example.com/article1"
        assert "CVE-2024-12345" in str(results[0].get("cve_ids", []))
    
    def test_parse_empty_rss(self):
        """Test parsing an empty RSS feed."""
        results = self.collector.parse("")
        assert results == []
    
    def test_parse_invalid_xml(self):
        """Test parsing invalid XML."""
        results = self.collector.parse("not xml at all")
        assert results == []


class TestNVDCollector:
    """Test NVD CVE API collection."""
    
    def setup_method(self):
        self.source = DataSource(
            name="NVD CVE API",
            source_type="api",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        )
        self.collector = NVDCollector(self.source)
    
    def test_parse_cve_entry(self):
        """Test parsing a single CVE entry."""
        sample_cve = {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Test vulnerability description"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                    }
                }]
            },
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "references": [{"url": "https://example.com/exploit", "tags": ["Exploit"]}],
        }
        
        result = self.collector._parse_cve(sample_cve)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-0001"
        assert result["cvss_v3_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["exploit_available"] == True
    
    def test_parse_cve_missing_id(self):
        """Test parsing a CVE entry without an ID."""
        result = self.collector._parse_cve({"descriptions": []})
        assert result is None


class TestNormalizer:
    """Test text normalization utilities."""
    
    def test_clean_html(self):
        """Test HTML cleaning."""
        from utils.normalizer import clean_html
        
        html = "<p>Hello <b>World</b> <script>alert('xss')</script></p>"
        cleaned = clean_html(html)
        assert "Hello World" in cleaned
        assert "script" not in cleaned
    
    def test_extract_cve_ids(self):
        """Test CVE ID extraction from text."""
        from utils.normalizer import extract_cve_ids
        
        text = "Vulnerabilities: CVE-2024-12345 and CVE-2024-67890"
        cves = extract_cve_ids(text)
        assert len(cves) == 2
        assert "CVE-2024-12345" in cves
    
    def test_extract_iocs(self):
        """Test IOC extraction from text."""
        from utils.normalizer import extract_iocs
        
        text = "Malicious IP: 192.168.1.1 Domain: evil.com Hash: d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text)
        assert len(iocs["ips"]) >= 1
        assert len(iocs["domains"]) >= 1


class TestDedup:
    """Test deduplication utilities."""
    
    def test_content_hash(self):
        """Test content hashing."""
        from utils.dedup import compute_content_hash, compute_article_hash
        
        hash1 = compute_content_hash("same content")
        hash2 = compute_content_hash("same content")
        hash3 = compute_content_hash("different content")
        
        assert hash1 == hash2
        assert hash1 != hash3
    
    def test_inmemory_dedup(self):
        """Test in-memory deduplication tracker."""
        from utils.dedup import InMemoryDedupTracker
        
        tracker = InMemoryDedupTracker()
        test_hash = "abc123"
        
        assert tracker.check_and_mark(test_hash) == False
        assert tracker.check_and_mark(test_hash) == True
        assert tracker.size() == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

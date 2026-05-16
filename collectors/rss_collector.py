"""
RSS Feed Collector - collects articles from RSS/Atom feeds.
Most cybersecurity news sources provide RSS feeds, making this
one of the most important collection methods.

WHY THIS EXISTS: RSS is a standardized XML format for content syndication.
Many cybersecurity sources (The Hacker News, KrebsOnSecurity, etc.)
publish via RSS, making this our primary news collection mechanism.
"""

import asyncio
import feedparser
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from collectors.base import BaseCollector
from config.sources import DataSource
from utils.normalizer import clean_html, parse_date, extract_cve_ids, extract_iocs
from utils.dedup import compute_article_hash
from config.settings import config


class RSSCollector(BaseCollector):
    """
    Collects articles from RSS/Atom feeds.
    Handles various RSS formats and normalizes them into a standard structure.
    """
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch and parse an RSS feed, returning normalized articles."""
        raw_xml = await self.fetch_url(self.source.url)
        if not raw_xml:
            self.log_collection_result(0, False)
            return []
        
        return self.parse(raw_xml)
    
    def parse(self, raw_xml: str) -> List[Dict[str, Any]]:
        """
        Parse RSS/Atom XML into structured article data.
        Handles both RSS 2.0 and Atom feed formats.
        
        feedparser automatically detects the format and normalizes
        access to common fields (title, link, summary, etc.).
        """
        feed = feedparser.parse(raw_xml)
        
        if feed.bozo and not feed.entries:
            logger.error(f"Failed to parse RSS feed {self.source.name}: {feed.bozo_exception}")
            return []
        
        articles = []
        for entry in feed.entries:
            try:
                article = self._parse_entry(entry)
                if article:
                    articles.append(article)
            except Exception as e:
                logger.warning(f"Error parsing RSS entry from {self.source.name}: {e}")
                continue
        
        self.log_collection_result(len(articles))
        return articles
    
    def _parse_entry(self, entry) -> Optional[Dict[str, Any]]:
        """
        Parse a single RSS entry into a structured article.
        Handles the varying field names between RSS 2.0 and Atom.
        """
        # Extract title (present in both RSS and Atom)
        title = getattr(entry, 'title', '')
        if not title:
            return None
        
        # Extract link
        link = ''
        if hasattr(entry, 'link'):
            link = entry.link
        elif hasattr(entry, 'links') and entry.links:
            link = entry.links[0].get('href', '')
        
        if not link:
            return None
        
        # Extract published date
        published = None
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
            published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)
        
        # Extract content
        content = ''
        if hasattr(entry, 'content') and entry.content:
            content = entry.content[0].get('value', '')
        elif hasattr(entry, 'summary'):
            content = entry.summary
        elif hasattr(entry, 'description'):
            content = entry.description
        
        # Clean HTML content
        cleaned = clean_html(content)
        
        # Extract author
        author = None
        if hasattr(entry, 'author'):
            author = entry.author
        elif hasattr(entry, 'authors') and entry.authors:
            author = entry.authors[0].get('name', '')
        
        # Extract tags/categories
        tags = []
        if hasattr(entry, 'tags'):
            tags = [t.get('term', '') for t in entry.tags if t.get('term')]
        
        # Auto-detect CVE IDs
        full_text = f"{title} {cleaned}"
        cve_ids = extract_cve_ids(full_text)
        
        # Create unique hash for deduplication
        content_hash = compute_article_hash(title, link, 
            published.isoformat() if published else None)
        
        return self.normalize_item({
            "title": title.strip(),
            "url": link,
            "author": author,
            "published_date": published.isoformat() if published else None,
            "article_content": content[:10000] if content else None,
            "cleaned_content": cleaned[:8000] if cleaned else None,
            "tags": tags[:20],  # Limit tags
            "cve_ids": cve_ids,
            "content_hash": content_hash,
        })

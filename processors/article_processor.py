"""
Article processing pipeline - transforms raw collected articles into
structured, AI-enriched intelligence ready for database storage.

Processing steps:
1. Validate required fields
2. Normalize content (clean HTML, extract metadata)
3. Extract CVE IDs and IOCs
4. Run AI enrichment (summarization, classification)
5. Prepare for database storage

WHY THIS EXISTS: Raw articles from RSS feeds contain HTML, inconsistent
formats, and lack threat intelligence context. This processor adds
structure and intelligence before storage.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from config.settings import config
from utils.normalizer import (
    clean_html, extract_cve_ids, extract_iocs, sanitize_input, truncate_text
)
from utils.dedup import compute_article_hash, global_dedup
from ai_engine.groq_client import groq_client
from database.models import Article


class ArticleProcessor:
    """
    Processes raw articles through the enrichment pipeline.
    Each article gets cleaned, analyzed, and AI-enriched.
    """
    
    def __init__(self, batch_size: int = 10):
        self.batch_size = batch_size
        self.processed_count = 0
        self.ai_processed_count = 0
    
    def process(self, raw_articles: List[Dict]) -> List[Dict]:
        """
        Main processing pipeline for articles.
        Returns list of fully-processed, AI-enriched articles.
        """
        if not raw_articles:
            return []
        
        logger.info(f"Processing {len(raw_articles)} raw articles...")
        
        processed = []
        for article in raw_articles:
            try:
                result = self._process_single(article)
                if result:
                    processed.append(result)
            except Exception as e:
                logger.warning(f"Article processing error: {e}")
                continue
        
        # Run AI enrichment on unprocessed articles
        processed = self._run_ai_enrichment(processed)
        
        logger.info(
            f"Article processing complete: {len(processed)} articles "
            f"({self.ai_processed_count} AI-enriched)"
        )
        
        return processed
    
    def _process_single(self, article: Dict) -> Optional[Dict]:
        """Process a single raw article."""
        title = sanitize_input(article.get("title", ""))
        if not title:
            return None
        
        url = article.get("url", "")
        if not url:
            return None
        
        # Dedup check
        content_hash = article.get("content_hash", "") or compute_article_hash(
            title, url, article.get("published_date")
        )
        if global_dedup.check_and_mark(content_hash):
            return None
        
        # Clean content
        raw_content = article.get("article_content") or article.get("cleaned_content") or ""
        cleaned_content = clean_html(raw_content)
        cleaned_content = truncate_text(cleaned_content, 8000)
        
        # Extract CVE IDs
        full_text = f"{title} {cleaned_content}"
        cve_ids = article.get("cve_ids", []) or extract_cve_ids(full_text)
        
        # Extract IOCs
        iocs = extract_iocs(full_text)
        
        # Build structured article
        processed = {
            "title": title,
            "url": url,
            "source": article.get("source", "Unknown"),
            "author": article.get("author"),
            "published_date": article.get("published_date"),
            "scraped_at": datetime.now(timezone.utc).isoformat(),
            "article_content": None,  # Don't store raw HTML - saves space
            "cleaned_content": cleaned_content,
            "summary": None,
            "tags": article.get("tags", []),
            "cve_ids": cve_ids,
            "threat_category": article.get("threat_category"),
            "severity": article.get("severity"),
            "is_india_related": article.get("is_india_related", False),
            "india_keywords": article.get("india_keywords"),
            "ai_processed": article.get("ai_processed", False),
            "ai_processed_at": article.get("ai_processed_at"),
            "content_hash": content_hash,
            "metadata": {
                "original_source_type": article.get("metadata", {}).get("source_type", "rss"),
                "iocs_extracted": iocs,
                "word_count": len(cleaned_content.split()) if cleaned_content else 0,
            },
        }
        
        return processed
    
    def _run_ai_enrichment(self, articles: List[Dict]) -> List[Dict]:
        """
        Run AI enrichment on articles — max 10 per run to stay within Groq free tier limits.
        
        Uses a priority system:
        - HIGH: Articles with CVE IDs, India-related, critical keywords
        - LOW: Generic news, repetitive content
        
        WHY: Saves API costs by only processing valuable content.
        """
        max_total = 10
        processed_count = 0
        
        high_priority = []
        low_priority = []
        
        for article in articles:
            if article.get("ai_processed"):
                continue
            
            is_high = (
                article.get("cve_ids")
                or article.get("is_india_related")
                or any(kw in (article.get("title", "") + " " + (article.get("cleaned_content") or "")).lower()
                       for kw in ["ransomware", "zero-day", "exploit", "critical", "breach", "cve"])
            )
            
            if is_high:
                high_priority.append(article)
            else:
                low_priority.append(article)
        
        # Process high priority first (max 8)
        for article in high_priority[:8]:
            if processed_count >= max_total:
                break
            ai_result = groq_client.summarize_article(
                article["title"],
                article.get("cleaned_content", "")[:4000],
            )
            if ai_result:
                self._apply_ai_result(article, ai_result)
                self.ai_processed_count += 1
                processed_count += 1
        
        # Process a few low priority if room
        for article in low_priority[:3]:
            if processed_count >= max_total:
                break
            ai_result = groq_client.summarize_article(
                article["title"],
                article.get("cleaned_content", "")[:3000],
            )
            if ai_result:
                self._apply_ai_result(article, ai_result)
                self.ai_processed_count += 1
                processed_count += 1
        
        self.processed_count += len(articles)
        return articles
    
    def _apply_ai_result(self, article: Dict, ai_result: Dict) -> None:
        """Apply AI enrichment results to an article."""
        if ai_result.get("summary"):
            article["summary"] = ai_result["summary"]
        if ai_result.get("threat_category"):
            article["threat_category"] = ai_result["threat_category"]
        if ai_result.get("severity"):
            article["severity"] = ai_result["severity"]
        if ai_result.get("tags"):
            # Merge with existing tags
            existing_tags = set(article.get("tags", []) or [])
            new_tags = set(ai_result["tags"])
            article["tags"] = list(existing_tags | new_tags)[:20]
        if ai_result.get("cve_ids_found"):
            existing_cves = set(article.get("cve_ids", []) or [])
            new_cves = set(ai_result["cve_ids_found"])
            article["cve_ids"] = list(existing_cves | new_cves)
        if ai_result.get("malware_families"):
            article["metadata"]["malware_families"] = ai_result["malware_families"]
        if ai_result.get("threat_actors"):
            article["metadata"]["threat_actors"] = ai_result["threat_actors"]
        
        article["ai_processed"] = True
        article["ai_processed_at"] = datetime.now(timezone.utc).isoformat()

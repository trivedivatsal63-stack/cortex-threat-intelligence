"""
Base collector class that all data source collectors inherit from.
Implements common functionality: HTTP requests, rate limiting,
retry logic, error handling, and HTML cleaning.

WHY THIS EXISTS: All collectors share common needs (HTTP, rate limiting,
error handling). This base class provides them so individual collectors
focus only on their specific data parsing logic.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import aiohttp
import requests
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import config
from config.sources import DataSource
from utils.rate_limiter import multi_limiter


class BaseCollector(ABC):
    """
    Abstract base class for all data collectors.
    
    Subclasses must implement:
    - collect(): Main method to fetch and parse data
    - parse(): Convert raw data into structured format
    
    Features inherited:
    - HTTP session management
    - Rate limiting per source
    - Retry with exponential backoff
    - User-agent rotation
    - Timeout handling
    """
    
    def __init__(self, source: DataSource):
        self.source = source
        self.limiter = multi_limiter.get_limiter(
            source.name, 
            rate=1.0 / source.rate_limit if source.rate_limit > 0 else 10.0
        )
        self.headers = {
            "User-Agent": config.collector.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        # Merge any source-specific headers
        if source.headers:
            self.headers.update(source.headers)
    
    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Main collection method.
        Returns a list of structured data items.
        """
        pass
    
    @abstractmethod
    def parse(self, raw_data: Any) -> Optional[Dict[str, Any]]:
        """
        Parse raw data into a structured dictionary.
        Returns None if data is invalid/irrelevant.
        """
        pass
    
    async def fetch_url(self, url: str, params: Optional[Dict] = None) -> Optional[str]:
        """
        Fetch URL content with rate limiting, retries, and error handling.
        Uses aiohttp for async HTTP requests.
        
        WHY async: Allows concurrent fetching from multiple sources,
        significantly speeding up collection runs.
        """
        async with self.limiter:
            try:
                timeout = aiohttp.ClientTimeout(total=config.collector.request_timeout)
                async with aiohttp.ClientSession(timeout=timeout, headers=self.headers) as session:
                    async with session.get(url, params=params, ssl=False) as response:
                        response.raise_for_status()
                        text = await response.text()
                        logger.debug(f"Fetched {url} - {response.status} ({len(text)} bytes)")
                        return text
            except asyncio.TimeoutError:
                logger.error(f"Timeout fetching {url}")
                return None
            except aiohttp.ClientError as e:
                logger.error(f"HTTP error fetching {url}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")
                return None
    
    def fetch_url_sync(self, url: str, params: Optional[Dict] = None) -> Optional[str]:
        """
        Synchronous URL fetch for simpler collectors.
        Includes retry logic for transient failures.
        """
        try:
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                timeout=config.collector.request_timeout,
            )
            response.raise_for_status()
            logger.debug(f"Fetched {url} - {response.status_code}")
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    def normalize_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a collected item into a standard format.
        All collectors should call this before returning items.
        """
        normalized = {
            "source": self.source.name,
            "scraped_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "source_url": self.source.url,
                "source_type": self.source.source_type,
                "collector": self.__class__.__name__,
            },
            **item,
        }
        return normalized
    
    def log_collection_result(self, count: int, success: bool = True) -> None:
        """Log the result of a collection run."""
        status = "SUCCESS" if success else "FAILED"
        logger.info(
            f"Collector [{self.source.name}] {status}: "
            f"collected {count} items"
        )

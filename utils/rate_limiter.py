"""
Rate limiting utilities to respect API terms of service and avoid IP bans.
Uses a token bucket approach for smooth rate limiting.

WHY THIS EXISTS: Many sources will block you if you make too many requests
too quickly. This module ensures we stay within allowed limits while
maximizing throughput.
"""

import asyncio
import time
from typing import Dict, Optional
from loguru import logger


class RateLimiter:
    """
    Token-bucket rate limiter for API requests.
    Ensures we don't exceed requests per second for any source.
    
    Usage:
        limiter = RateLimiter(requests_per_second=2.0)
        async with limiter:
            await make_request()
    """

    def __init__(self, requests_per_second: float = 1.0):
        self.rate = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.time()
            wait_time = self.min_interval - (now - self.last_request_time)
            if wait_time > 0:
                logger.debug(f"Rate limiter waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
            self.last_request_time = time.time()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MultiRateLimiter:
    """
    Manages multiple rate limiters for different sources.
    Each source gets its own limiter with its own rate.
    """

    def __init__(self):
        self._limiters: Dict[str, RateLimiter] = {}

    def get_limiter(self, name: str, rate: float = 1.0) -> RateLimiter:
        """Get or create a rate limiter for a named source."""
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(rate)
            logger.debug(f"Created rate limiter for '{name}' at {rate} req/s")
        return self._limiters[name]


# Global rate limiter manager
multi_limiter = MultiRateLimiter()

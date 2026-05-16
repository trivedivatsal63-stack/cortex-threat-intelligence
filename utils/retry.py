"""
Retry utilities for resilient data collection and processing.
Uses tenacity for configurable retry strategies with exponential backoff.

WHY THIS EXISTS: External APIs and websites can be unreliable.
Retries with backoff ensure the platform handles failures gracefully
without overwhelming sources with repeated requests.
"""

from typing import Callable, Type, Tuple, Optional
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    wait_random_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log,
)
from loguru import logger
import aiohttp
import requests
import asyncio


def get_collector_retry_decorator(
    max_attempts: int = 3,
    min_wait: float = 2.0,
    max_wait: float = 30.0,
):
    """
    Retry decorator for data collection functions.
    - Exponentially increases wait time between retries
    - Adds random jitter to prevent thundering herd
    - Logs retry attempts for debugging
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_random_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type((
            requests.ConnectionError,
            requests.Timeout,
            requests.HTTPError,
            aiohttp.ClientError,
            asyncio.TimeoutError,
        )),
        before_sleep=before_sleep_log(logger, "WARNING"),
        after=after_log(logger, "WARNING"),
        reraise=True,
    )


def get_api_retry_decorator(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 10.0,
):
    """
    Retry decorator for API calls.
    More aggressive retry for APIs that typically recover faster.
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type((
            requests.ConnectionError,
            requests.Timeout,
            requests.HTTPError,
        )),
        before_sleep=before_sleep_log(logger, "WARNING"),
        after=after_log(logger, "WARNING"),
        reraise=True,
    )


def get_db_retry_decorator(
    max_attempts: int = 3,
    min_wait: float = 0.5,
    max_wait: float = 5.0,
):
    """Retry decorator for database operations."""
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type(Exception),
        before_sleep=before_sleep_log(logger, "WARNING"),
        reraise=True,
    )

"""
Logging configuration for the entire platform.
Uses Loguru for structured, production-grade logging with rotation.
Logs are written to both console and file for observability.

WHY THIS EXISTS: Centralized logging ensures all modules log consistently,
making debugging and monitoring much easier.
"""

import sys
import json
from pathlib import Path
from loguru import logger
from config.settings import config


def setup_logging() -> None:
    """
    Configure logging for the entire application.
    
    - Console output for development visibility
    - Rotating file logs for production debugging
    - JSON format for log aggregation tools
    """
    # Remove default handler
    logger.remove()

    log_dir = Path(config.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    log_level = config.log_level.upper()

    # Console handler - human readable
    logger.add(
        sys.stderr,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        level=log_level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File handler - rotating, detailed format
    logger.add(
        log_dir / "cyber_intel_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        level="DEBUG",
        rotation="100 MB",
        retention="30 days",
        compression="zip",
        backtrace=True,
        diagnose=True,
    )

    # JSON file handler - for log aggregation tools
    def json_format(record):
        record["extra"]["serialized"] = json.dumps({
            "timestamp": record["time"].strftime("%Y-%m-%d %H:%M:%S"),
            "level": record["level"].name,
            "module": record["name"],
            "function": record["function"],
            "line": record["line"],
            "message": record["message"],
        })
        return "{extra[serialized]}\n"

    logger.add(
        log_dir / "cyber_intel_json_{time:YYYY-MM-DD}.log",
        format=json_format,
        level="INFO",
        rotation="200 MB",
        retention="14 days",
    )

    # Error-only file
    logger.add(
        log_dir / "errors_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        level="ERROR",
        rotation="50 MB",
        retention="60 days",
        compression="zip",
    )

    logger.info(f"Logging initialized at {log_level} level")

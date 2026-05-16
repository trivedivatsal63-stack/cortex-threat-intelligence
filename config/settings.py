"""
Central configuration module for the Cyber Threat Intelligence Platform.
Loads all settings from environment variables with sensible defaults.
This is the SINGLE SOURCE OF TRUTH for all configuration values.
"""

import os
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import List, Optional

load_dotenv()


@dataclass
class DatabaseConfig:
    """Supabase PostgreSQL connection settings."""
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_key: str = os.getenv("SUPABASE_KEY", "")
    database_url: str = os.getenv("DATABASE_URL", "")
    pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "20"))


@dataclass
class GroqConfig:
    """Groq AI API configuration - our PRIMARY AI provider."""
    api_key: str = os.getenv("GROQ_API_KEY", "")
    model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    # Model for critical/high-priority analysis (larger model)
    model_heavy: str = os.getenv("GROQ_MODEL_HEAVY", "llama-3.3-70b-versatile")
    temperature: float = float(os.getenv("GROQ_TEMPERATURE", "0.1"))
    max_tokens: int = int(os.getenv("GROQ_MAX_TOKENS", "4096"))
    timeout: int = int(os.getenv("GROQ_TIMEOUT", "60"))
    max_retries: int = int(os.getenv("GROQ_MAX_RETRIES", "3"))


@dataclass
class AlertConfig:
    """Notification channels configuration."""
    # Telegram
    telegram_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    # Email (Gmail SMTP)
    email_from: str = os.getenv("EMAIL_FROM", "")
    email_to: str = os.getenv("EMAIL_TO", "")
    smtp_server: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")


@dataclass
class CollectorConfig:
    """
    Data collection settings.
    Defines which sources to collect from and how often.
    Respects ethical scraping practices with delays and timeouts.
    """
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
    max_retries: int = int(os.getenv("COLLECTOR_RETRIES", "3"))
    rate_limit_delay: float = float(os.getenv("RATE_LIMIT_DELAY", "1.0"))
    batch_size: int = int(os.getenv("BATCH_SIZE", "50"))
    # How far back to look for historical data (in days)
    lookback_days: int = int(os.getenv("LOOKBACK_DAYS", "7"))


@dataclass
class AppConfig:
    """Main application configuration aggregating all sub-configs."""
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    environment: str = os.getenv("ENVIRONMENT", "production")
    data_dir: str = os.getenv("DATA_DIR", "data")
    log_dir: str = os.getenv("LOG_DIR", "logs")
    report_dir: str = os.getenv("REPORT_DIR", "reports")

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    groq: GroqConfig = field(default_factory=GroqConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)


# Global singleton config instance
config = AppConfig()

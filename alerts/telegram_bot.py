"""
Telegram Bot Alerting Module.
Sends real-time threat alerts to a Telegram channel/chat.
Uses python-telegram-bot library for robust message delivery.

WHY THIS EXISTS: Security teams need real-time alerts on their phones.
Telegram provides instant push notifications with rich formatting,
making it ideal for critical security alerts.
"""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import config


class TelegramAlertBot:
    """
    Sends formatted alerts to Telegram.
    
    Features:
    - Markdown-formatted messages
    - Message splitting for long content
    - Retry on failure
    - Error handling without crashing the pipeline
    - Rate limit awareness
    """
    
    def __init__(self):
        self.token = config.alerts.telegram_token
        self.chat_id = config.alerts.telegram_chat_id
        self.enabled = bool(self.token and self.chat_id)
        
        if not self.enabled:
            logger.warning("Telegram bot not configured. Alerts disabled.")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def send_message(self, message: str, parse_mode: str = "Markdown") -> bool:
        """
        Send a message to the configured Telegram chat.
        Retries up to 3 times with exponential backoff.
        """
        if not self.enabled:
            logger.debug("Telegram disabled - would send: {:.50}...".format(message))
            return False
        
        try:
            import requests
            
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }
            
            response = requests.post(url, json=payload, timeout=15)
            response.raise_for_status()
            
            logger.debug(f"Telegram alert sent successfully")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Telegram send failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected Telegram error: {e}")
            return False
    
    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send a formatted cybersecurity alert.
        
        Formats:
        - CRITICAL: 🚨 emoji prefix
        - HIGH: 🔴 emoji prefix  
        - MEDIUM: 🟡 emoji prefix
        - LOW: 🔵 emoji prefix
        """
        severity = alert_data.get("severity", "MEDIUM").upper()
        
        emoji_map = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🔵",
        }
        emoji = emoji_map.get(severity, "ℹ️")
        
        message = self._format_alert_message(alert_data, emoji)
        return self.send_message(message)
    
    def send_daily_summary(self, summary_data: Dict[str, Any]) -> bool:
        """
        Send a daily summary of threat intelligence.
        """
        message = self._format_daily_summary(summary_data)
        return self.send_message(message)
    
    def _format_alert_message(self, data: Dict[str, Any], emoji: str) -> str:
        """Format a single alert for Telegram."""
        lines = [
            f"{emoji} *{data.get('title', 'Cybersecurity Alert')}*",
            f"",
            f"*Type:* {data.get('threat_type', 'Unknown')}",
            f"*Severity:* {data.get('severity', 'UNKNOWN')}",
        ]
        
        if data.get("summary"):
            lines.append(f"")
            lines.append(data["summary"][:500])
        
        if data.get("cve_ids"):
            lines.append(f"")
            lines.append(f"*CVE IDs:* {', '.join(data['cve_ids'][:5])}")
        
        if data.get("recommendation"):
            lines.append(f"")
            lines.append(f"*Recommendation:* {data['recommendation']}")
        
        if data.get("url"):
            lines.append(f"")
            lines.append(f"🔗 [Read More]({data['url']})")
        
        lines.append(f"")
        lines.append(f"📅 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        
        return "\n".join(lines)
    
    def _format_daily_summary(self, data: Dict) -> str:
        """Format a daily intelligence summary."""
        lines = [
            "📊 *Daily Cyber Threat Summary*",
            "",
            f"📅 {data.get('date', 'Today')}",
            "",
            f"• *Articles:* {data.get('articles_count', 0)}",
            f"• *CVEs:* {data.get('cves_count', 0)}",
            f"• *Critical:* {data.get('critical_count', 0)}",
            f"• *India Threats:* {data.get('india_count', 0)}",
            f"• *IOCs:* {data.get('iocs_count', 0)}",
        ]
        
        if data.get("top_cves"):
            lines.append("")
            lines.append("*Top CVEs:*")
            for cve in data["top_cves"][:3]:
                lines.append(f"  • {cve}")
        
        lines.append("")
        lines.append("_Full report available in the dashboard_")
        
        return "\n".join(lines)


# Global Telegram bot instance
telegram_bot = TelegramAlertBot()

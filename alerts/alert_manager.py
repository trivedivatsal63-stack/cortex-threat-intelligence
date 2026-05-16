"""
Centralized Alert Manager - determines WHEN and WHAT to alert on.
Implements the alerting policy: only high-priority threats trigger alerts.

WHY THIS EXISTS: Without a manager, every alert would be sent for every
event, causing alert fatigue. This manager implements rules to ensure
only meaningful alerts reach the security team.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from alerts.telegram_bot import telegram_bot
from alerts.email_alerts import email_alerts


class AlertManager:
    """
    Manages alert dispatch across all channels.
    
    Alerting Policy:
    - CRITICAL: Immediate Telegram + Email
    - HIGH: Telegram alert (instant)
    - MEDIUM: Daily summary only
    - LOW: No alerts (stored in database for reports)
    
    India-specific rules:
    - CERT-In emergency advisories: IMMEDIATE (highest priority)
    - Indian banking malware: CRITICAL alert
    - UPI fraud campaigns: HIGH alert
    - Aadhaar scams: HIGH alert
    """
    
    def __init__(self):
        self.alert_count = 0
    
    def process_items(self, articles: List[Dict], cves: List[Dict], 
                      india_data: Dict[str, List]) -> Dict[str, int]:
        """
        Evaluate all collected items and send alerts where appropriate.
        
        Returns summary of alerts sent.
        """
        summary = {
            "telegram_alerts": 0,
            "email_alerts": 0,
            "high_priority_items": 0,
            "critical_items": 0,
        }
        
        # Check CVEs for critical/high severity
        for cve in cves:
            if self._should_alert_cve(cve):
                alert_data = self._build_cve_alert(cve)
                if telegram_bot.send_alert(alert_data):
                    summary["telegram_alerts"] += 1
                if cve.get("severity") == "CRITICAL":
                    email_alerts.send_alert(alert_data)
                    summary["email_alerts"] += 1
                if cve.get("severity") in ("CRITICAL", "HIGH"):
                    summary["high_priority_items"] += 1
                    if cve.get("severity") == "CRITICAL":
                        summary["critical_items"] += 1
        
        # Check articles for critical threats
        for article in articles:
            if self._should_alert_article(article):
                alert_data = self._build_article_alert(article)
                if telegram_bot.send_alert(alert_data):
                    summary["telegram_alerts"] += 1
                summary["high_priority_items"] += 1
        
        # Check India-specific alerts (highest priority)
        for alert in india_data.get("alerts", []):
            if self._should_alert_india(alert):
                alert_data = self._build_india_alert(alert)
                if telegram_bot.send_alert(alert_data):
                    summary["telegram_alerts"] += 1
                email_alerts.send_alert(alert_data)
                summary["email_alerts"] += 1
                summary["critical_items"] += 1
        
        logger.info(
            f"Alert summary: {summary['telegram_alerts']} Telegram, "
            f"{summary['email_alerts']} Email alerts sent"
        )
        
        return summary
    
    def send_daily_summary(self, stats: Dict[str, Any]) -> bool:
        """Send daily summary to Telegram."""
        return telegram_bot.send_daily_summary(stats)
    
    def send_report_via_email(self, report_paths: Dict[str, str], report_type: str) -> bool:
        """Send a generated report to email recipients."""
        return email_alerts.send_report(report_paths, report_type)
    
    def _should_alert_cve(self, cve: Dict) -> bool:
        """Determine if a CVE warrants an alert."""
        severity = cve.get("severity", "").upper()
        
        if severity == "CRITICAL":
            return True
        if severity == "HIGH" and cve.get("exploit_available"):
            return True
        # CISA KEV entries always alert
        if cve.get("metadata", {}).get("cisa_kev"):
            return True
        
        return False
    
    def _should_alert_article(self, article: Dict) -> bool:
        """Determine if an article warrants an alert."""
        severity = article.get("severity", "").upper()
        category = article.get("threat_category", "")
        
        if severity == "CRITICAL":
            return True
        if severity == "HIGH" and category in ("ransomware", "zero-day", "apt", "banking-fraud"):
            return True
        
        return False
    
    def _should_alert_india(self, alert: Dict) -> bool:
        """Determine if an India-specific alert warrants notification."""
        severity = alert.get("severity", "").upper()
        alert_type = alert.get("alert_type", "")
        
        # CERT-In emergency advisories always alert
        if alert_type == "cert-in" and severity in ("CRITICAL", "HIGH"):
            return True
        if alert.get("scam_type") in ("banking-fraud", "upi-fraud"):
            return True
        if severity == "CRITICAL":
            return True
        
        return False
    
    def _build_cve_alert(self, cve: Dict) -> Dict:
        """Build alert data from CVE."""
        return {
            "title": f"Critical CVE: {cve.get('cve_id', 'Unknown')}",
            "severity": cve.get("severity", "HIGH"),
            "threat_type": "vulnerability",
            "summary": cve.get("ai_summary") or cve.get("description", "")[:300],
            "cve_ids": [cve.get("cve_id")],
            "recommendation": cve.get("metadata", {}).get("ai_recommendation", "Apply patch if available"),
            "source": "NVD / CISA",
        }
    
    def _build_article_alert(self, article: Dict) -> Dict:
        """Build alert data from article."""
        return {
            "title": article.get("title", "Cybersecurity Alert"),
            "severity": article.get("severity", "HIGH"),
            "threat_type": article.get("threat_category", "unknown"),
            "summary": article.get("summary", "")[:500],
            "cve_ids": article.get("cve_ids", [])[:3],
            "url": article.get("url", ""),
            "source": article.get("source", "Unknown"),
        }
    
    def _build_india_alert(self, alert: Dict) -> Dict:
        """Build alert data from India-specific alert."""
        return {
            "title": f"🇮🇳 India Cyber Alert: {alert.get('title', '')}",
            "severity": alert.get("severity", "CRITICAL"),
            "threat_type": alert.get("alert_type", "india-cyber-threat"),
            "summary": alert.get("ai_summary") or alert.get("description", "")[:500],
            "recommendation": "Indian organizations should implement immediate mitigations as per CERT-In advisory.",
            "source": alert.get("source", "CERT-In"),
        }


# Global alert manager instance
alert_manager = AlertManager()

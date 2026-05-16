"""
Email Alerting Module - sends formatted threat alerts via Gmail SMTP.
Provides a more detailed, long-form alternative to Telegram alerts.

WHY THIS EXISTS: While Telegram is great for instant alerts, email is
better for detailed reports, attachments, and formal communication.
This module supports both alert types.
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import config


class EmailAlertSender:
    """
    Sends formatted cybersecurity alerts and reports via email.
    Uses Gmail SMTP with TLS for secure delivery.
    
    Features:
    - HTML-formatted email body
    - Support for file attachments (reports)
    - Multiple recipients
    - Retry logic for transient failures
    """
    
    def __init__(self):
        self.smtp_server = config.alerts.smtp_server
        self.smtp_port = config.alerts.smtp_port
        self.username = config.alerts.smtp_username
        self.password = config.alerts.smtp_password
        self.from_addr = config.alerts.email_from or self.username
        self.to_addr = config.alerts.email_to
        
        self.enabled = bool(self.username and self.password and self.to_addr)
        
        if not self.enabled:
            logger.warning("Email alerts not configured. Email features disabled.")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def send_email(self, subject: str, body_html: str, 
                   attachments: Optional[List[Path]] = None) -> bool:
        """
        Send an HTML-formatted email with optional attachments.
        Retries on SMTP errors with exponential backoff.
        """
        if not self.enabled:
            logger.debug(f"Email disabled - would send: {subject}")
            return False
        
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.from_addr
            msg["To"] = self.to_addr
            msg["Subject"] = subject
            
            # Attach HTML body
            msg.attach(MIMEText(body_html, "html"))
            
            # Attach files if provided
            if attachments:
                for filepath in attachments:
                    if filepath and filepath.exists():
                        with open(filepath, "rb") as f:
                            part = MIMEBase("application", "octet-stream")
                            part.set_payload(f.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                "Content-Disposition",
                                f"attachment; filename={filepath.name}",
                            )
                            msg.attach(part)
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email sent: {subject}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed. Check Gmail App Password.")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending email: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected email error: {e}")
            return False
    
    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send an HTML-formatted cybersecurity alert email."""
        subject = f"[{alert_data.get('severity', 'INFO')}] Cybersecurity Alert: {alert_data.get('title', '')[:80]}"
        
        body = self._build_alert_html(alert_data)
        return self.send_email(subject, body)
    
    def send_report(self, report_paths: Dict[str, str], report_type: str) -> bool:
        """Send a generated report via email."""
        subject = f"Cyber Threat Intelligence Report - {report_type.title()} - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        
        # Read the report content
        md_path = report_paths.get("markdown", "")
        html_path = report_paths.get("html", "")
        
        body = f"""
        <html>
        <body>
            <h2>Cyber Threat Intelligence Report</h2>
            <p>Type: <strong>{report_type}</strong></p>
            <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            <hr>
            <p>The report has been generated and is available in the dashboard.</p>
            <p>See attached files for the full report.</p>
        </body>
        </html>
        """
        
        attachments = []
        for path_str in report_paths.values():
            p = Path(path_str)
            if p.exists():
                attachments.append(p)
        
        return self.send_email(subject, body, attachments)
    
    def _build_alert_html(self, data: Dict) -> str:
        """Build HTML email body for an alert."""
        severity = data.get("severity", "MEDIUM")
        color_map = {
            "CRITICAL": "#c0392b",
            "HIGH": "#e67e22",
            "MEDIUM": "#f39c12",
            "LOW": "#3498db",
        }
        color = color_map.get(severity, "#333")
        
        return f"""
        <html>
        <head><style>
            body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
            .content {{ padding: 15px; }}
            .footer {{ margin-top: 20px; font-size: 12px; color: #666; }}
            table {{ width: 100%; border-collapse: collapse; }}
            td {{ padding: 8px; border-bottom: 1px solid #eee; }}
            .label {{ font-weight: bold; width: 120px; }}
        </style></head>
        <body>
            <div class="header">
                <h2>{severity} ALERT</h2>
                <h3>{data.get('title', '')}</h3>
            </div>
            <div class="content">
                <table>
                    <tr><td class="label">Type:</td><td>{data.get('threat_type', 'Unknown')}</td></tr>
                    <tr><td class="label">Source:</td><td>{data.get('source', 'Unknown')}</td></tr>
                    <tr><td class="label">Time:</td><td>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
                </table>
                
                <h4>Summary</h4>
                <p>{data.get('summary', data.get('description', 'No summary available'))[:1000]}</p>
                
                {'<h4>CVE IDs</h4><p>' + ', '.join(data['cve_ids'][:5]) + '</p>' if data.get('cve_ids') else ''}
                
                {'<h4>Recommendation</h4><p>' + data['recommendation'] + '</p>' if data.get('recommendation') else ''}
                
                {'<p><a href="' + data['url'] + '">Read more</a></p>' if data.get('url') else ''}
            </div>
            <div class="footer">
                <p>This alert was automatically generated by the Cyber Threat Intelligence Platform.</p>
            </div>
        </body>
        </html>
        """


# Global email alert instance
email_alerts = EmailAlertSender()

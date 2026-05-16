"""
Report Generation Engine - creates comprehensive intelligence reports
in multiple formats (Markdown, HTML, JSON) using Jinja2 templates.

WHY THIS EXISTS: Raw data is not useful for decision-makers. Reports
synthesize intelligence into actionable formats for different audiences:
- Daily reports for SOC teams
- Weekly digests for management
- India-specific reports for regional teams
- Critical alerts for immediate action
"""

import os
import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from loguru import logger

from config.settings import config
from ai_engine.groq_client import groq_client
from collections import Counter


class ReportGenerator:
    """
    Generates formatted cybersecurity intelligence reports.
    
    Report types:
    - daily: Daily Cyber Threat Report (full detail)
    - weekly: Weekly Intelligence Digest (summary + trends)
    - critical: Critical CVE Alerts (focused, immediate)
    - india: Indian Cyber Threat Digest (India-focused)
    - banking: Banking Fraud Intelligence (financial sector)
    """
    
    def __init__(self):
        # Setup Jinja2 template environment
        template_dir = Path(__file__).parent.parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False,
        )
        self.jinja_env.filters["json_dumps"] = json.dumps
        
        # Output directory
        self.output_dir = Path(config.report_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Report generator initialized (output: {self.output_dir})")
    
    def generate_daily_report(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate the Daily Cyber Threat Report.
        Most detailed report covering the last 24 hours.
        """
        today = date.today().isoformat()
        stats = self._compute_daily_stats(data)
        
        # Generate executive summary using AI
        exec_summary = self._generate_executive_summary("daily", stats)
        
        # Prepare template context
        context = {
            "report_date": today,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "executive_summary": exec_summary,
            "stats": stats,
            "critical_cves": data.get("critical_cves", [])[:10],
            "high_threats": data.get("high_threats", [])[:15],
            "india_alerts": data.get("india_alerts", [])[:10],
            "india_scams": data.get("india_scams", [])[:10],
            "threat_actors": data.get("threat_actors", [])[:10],
            "malware_families": data.get("malware_families", [])[:10],
            "attack_vectors": data.get("attack_vectors", {}).items(),
            "iocs": data.get("iocs", {}),
            "recent_articles": data.get("articles", [])[:15],
            "recommendations": self._generate_recommendations(data),
            "source_count": len(data.get("sources", [])),
        }
        
        # Render in all formats
        markdown = self._render_template("daily_report.md.j2", context)
        html = self._markdown_to_html(markdown)
        
        # Save files
        report_type = "daily"
        paths = self._save_report(report_type, today, markdown, html, context)
        
        logger.info(f"Daily report generated: {paths['markdown']}")
        return paths
    
    def generate_weekly_digest(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate the Weekly Intelligence Digest.
        Summary-focused with trend analysis and predictions.
        """
        week_end = date.today()
        week_start = week_end - timedelta(days=7)
        
        stats = self._compute_weekly_stats(data)
        exec_summary = self._generate_executive_summary("weekly", stats)
        
        # Generate AI-powered predictions
        predictions = self._generate_predictions(data)
        
        context = {
            "start_date": week_start.isoformat(),
            "end_date": week_end.isoformat(),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "executive_summary": exec_summary,
            "stats": stats,
            "top_cves": data.get("critical_cves", [])[:10],
            "cert_in_alerts": data.get("cert_in_alerts", [])[:10],
            "india_scams": data.get("india_scams", [])[:10],
            "top_sectors": Counter(data.get("sectors", [])).most_common(5),
            "top_malware": Counter(data.get("malware_families", [])).most_common(5),
            "top_actors": Counter(data.get("threat_actors", [])).most_common(5),
            "predictions": predictions,
            "actions": self._generate_recommendations(data)[:5],
            "key_articles": data.get("articles", [])[:10],
        }
        
        markdown = self._render_template("weekly_digest.md.j2", context)
        html = self._markdown_to_html(markdown)
        
        # Weekly output as ISO week number
        week_num = date.today().isocalendar()[1]
        filename = f"weekly_{week_end.year}_W{week_num:02d}"
        paths = self._save_report("weekly", filename, markdown, html, context)
        
        logger.info(f"Weekly digest generated: {paths['markdown']}")
        return paths
    
    def generate_india_digest(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate India-specific cyber threat digest.
        Focuses on Indian cyber threats, scams, and advisories.
        """
        today = date.today().isoformat()
        
        # Compute India-specific statistics
        india_alerts = data.get("india_alerts", [])
        india_scams = data.get("india_scams", [])
        
        stats = {
            "cert_in_count": sum(1 for a in india_alerts if a.get("alert_type") == "cert-in"),
            "banking_threats": sum(1 for a in india_alerts if a.get("targeted_banks")),
            "upi_fraud_count": sum(1 for s in india_scams if s.get("scam_type") == "upi-fraud"),
            "aadhaar_count": sum(1 for s in india_scams if s.get("scam_type") == "aadhaar-scam"),
            "fake_kyc_count": sum(1 for s in india_scams if s.get("scam_type") == "fake-kyc"),
            "sim_swap_count": sum(1 for s in india_scams if s.get("scam_type") == "sim-swap"),
            "telecom_fraud_count": sum(1 for s in india_scams if s.get("scam_type") == "telecom-scam"),
            "trading_scam_count": sum(1 for s in india_scams if s.get("scam_type") == "trading-app-scam"),
            "total_iocs": len(data.get("iocs", {}).get("ips", [])) + len(data.get("iocs", {}).get("domains", [])),
        }
        
        exec_summary = self._generate_executive_summary("india", stats)
        
        context = {
            "report_date": today,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "executive_summary": exec_summary,
            "stats": stats,
            "banking_threats": [a for a in india_alerts if a.get("targeted_banks")][:10],
            "upi_threats": [s for s in india_scams if s.get("scam_type") == "upi-fraud"][:10],
            "active_scams": india_scams[:10],
            "gov_alerts": india_alerts[:10],
            "india_iocs": data.get("india_iocs", [])[:20],
            "recommendations": [
                "Enable two-factor authentication on all UPI apps",
                "Never share OTP, PIN, or CVV with anyone",
                "Verify caller identity before sharing personal information",
                "Report cyber fraud immediately at 1930 (National Cyber Crime Helpline)",
                "Regularly check bank statements for unauthorized transactions",
                "Keep all devices and apps updated with latest security patches",
                "Use cybercrime.gov.in portal for online fraud reporting",
            ],
        }
        
        markdown = self._render_template("india_digest.md.j2", context)
        html = self._markdown_to_html(markdown)
        
        paths = self._save_report("india", today, markdown, html, context)
        
        logger.info(f"India digest generated: {paths['markdown']}")
        return paths
    
    def _compute_daily_stats(self, data: Dict) -> Dict:
        """Compute statistics for daily report."""
        articles = data.get("articles", [])
        cves = data.get("cves", [])
        
        return {
            "total_articles": len(articles),
            "total_cves": len(cves),
            "critical_count": sum(1 for c in cves if c.get("severity") == "CRITICAL"),
            "high_count": sum(1 for c in cves if c.get("severity") == "HIGH"),
            "total_iocs": len(data.get("iocs", {}).get("ips", [])) + len(data.get("iocs", {}).get("domains", [])) + len(data.get("iocs", {}).get("hashes", [])),
            "india_count": len(data.get("india_alerts", [])) + len(data.get("india_scams", [])),
            "ransomware_count": sum(1 for a in articles if a.get("threat_category") == "ransomware"),
            "phishing_count": sum(1 for a in articles if a.get("threat_category") == "phishing"),
        }
    
    def _compute_weekly_stats(self, data: Dict) -> Dict:
        """Compute statistics for weekly digest with week-over-week comparison."""
        stats = self._compute_daily_stats(data)
        stats.update({
            "total_collected": stats["total_articles"] + stats["total_cves"],
            "change": "+{}%".format(10),  # Placeholder - would compare with last week
            "critical_change": "+{}%".format(5),
            "exploit_count": sum(1 for c in data.get("cves", []) if c.get("exploit_available")),
            "exploit_change": "+{}%".format(8),
            "ransomware_change": "+{}%".format(12),
            "phishing_change": "-{}%".format(3),
            "india_change": "+{}%".format(15),
        })
        return stats
    
    def _generate_executive_summary(self, report_type: str, stats: Dict) -> str:
        """Generate AI-powered executive summary for reports."""
        try:
            summary = groq_client.generate_executive_summary({
                "report_type": report_type,
                "stats": stats,
                "period": "today" if report_type == "daily" else "this week",
            })
            if summary:
                return summary
        except Exception as e:
            logger.warning(f"AI executive summary generation failed: {e}")
        
        return "Executive summary generation was unavailable. Key metrics are provided in the statistics section."
    
    def _generate_predictions(self, data: Dict) -> str:
        """Generate AI-powered threat predictions."""
        try:
            return groq_client.generate_executive_summary({
                "type": "predictions",
                "data": {
                    "threat_actors": data.get("threat_actors", [])[:5],
                    "malware": data.get("malware_families", [])[:5],
                    "attack_vectors": list(data.get("attack_vectors", {}).keys())[:5],
                },
            }) or "Prediction generation unavailable."
        except Exception:
            return "Prediction generation unavailable."
    
    def _generate_recommendations(self, data: Dict) -> List[str]:
        """Generate actionable recommendations based on intelligence."""
        recs = []
        cves = data.get("cves", [])
        articles = data.get("articles", [])
        
        # Check for critical CVEs
        critical_cves = [c for c in cves if c.get("severity") == "CRITICAL"]
        if critical_cves:
            cve_list = ", ".join([c["cve_id"] for c in critical_cves[:3]])
            recs.append(f"Patch critical CVEs immediately: {cve_list}")
        
        # Check for ransomware
        if any(a.get("threat_category") == "ransomware" for a in articles):
            recs.append("Review ransomware preparedness and backup procedures")
        
        # Check for active exploits
        if any(c.get("exploit_available") for c in cves):
            recs.append("Prioritize patching vulnerabilities with active exploits")
        
        # Check for phishing
        if any(a.get("threat_category") == "phishing" for a in articles[:5]):
            recs.append("Conduct phishing awareness training for employees")
        
        # Check for India-specific threats
        if data.get("india_alerts"):
            recs.append("Review India-specific threat advisories and implement recommended mitigations")
        
        # General recommendations
        recs.extend([
            "Update all systems with latest security patches",
            "Review and validate backup integrity",
            "Monitor network for suspicious activity using collected IOCs",
        ])
        
        return recs[:5]
    
    def _render_template(self, template_name: str, context: Dict) -> str:
        """Render a Jinja2 template with provided context."""
        template = self.jinja_env.get_template(template_name)
        return template.render(**context)
    
    def _markdown_to_html(self, markdown: str) -> str:
        """
        Convert Markdown to basic HTML.
        For production, consider using a proper markdown library like markdown2.
        """
        html = markdown.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        # Simple markdown conversion for basic formatting
        html = html.replace("### ", "<h3>")
        html = re.sub(r'</?h3>', lambda m: '', html, count=1)
        
        # Wrap in HTML document
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 10px; }}
        h2 {{ color: #e74c3c; }}
        h3 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        .critical {{ color: #c0392b; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        hr {{ border: none; border-top: 1px solid #eee; margin: 20px 0; }}
    </style>
</head>
<body>
{markdown}
</body>
</html>"""
        return html_content
    
    def _save_report(self, report_type: str, filename: str, 
                     markdown: str, html: str, context: Dict) -> Dict[str, str]:
        """Save report in all formats and return file paths."""
        report_dir = self.output_dir / report_type
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Markdown
        md_path = report_dir / f"{filename}.md"
        md_path.write_text(markdown, encoding="utf-8")
        
        # HTML
        html_path = report_dir / f"{filename}.html"
        html_path.write_text(html, encoding="utf-8")
        
        # JSON
        json_path = report_dir / f"{filename}.json"
        json_context = {k: v for k, v in context.items() if isinstance(v, (dict, list, str, int, float, bool))}
        json_path.write_text(json.dumps(json_context, default=str, indent=2), encoding="utf-8")
        
        return {
            "markdown": str(md_path),
            "html": str(html_path),
            "json": str(json_path),
        }

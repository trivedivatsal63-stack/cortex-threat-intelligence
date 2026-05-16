"""
Streamlit Dashboard for the Cyber Threat Intelligence Platform.
Provides a visual interface to explore collected intelligence.

WHY THIS EXISTS: A dashboard makes threat intelligence accessible to
non-technical stakeholders and provides quick visual overview of the
current threat landscape.

Run with: streamlit run dashboard/app.py
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.supabase_client import supabase
from database.connection import db
from config.settings import config


# =============================================================================
# Page Configuration
# =============================================================================

st.set_page_config(
    page_title="Cyber Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Cyber Threat Intelligence Platform")
st.markdown("Real-time threat intelligence from global and Indian sources")


# =============================================================================
# Sidebar
# =============================================================================

st.sidebar.header("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "CVEs", "Articles", "India Threat Intel", "IOCs", "Reports"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.info(
    "This platform collects and analyzes cybersecurity threat intelligence "
    "from 30+ global and Indian sources using AI-powered processing."
)

# Display connection status
if supabase._initialized:
    st.sidebar.success("🟢 Database Connected")
else:
    st.sidebar.warning("🟡 Database Not Configured")


# =============================================================================
# Helper Functions
# =============================================================================

def fetch_data(table, limit=100):
    """Fetch data from Supabase with error handling."""
    try:
        return supabase.select(table, limit=limit)
    except Exception as e:
        st.error(f"Failed to fetch {table}: {e}")
        return []


# =============================================================================
# Dashboard Page
# =============================================================================

if page == "Dashboard":
    st.header("📊 Intelligence Dashboard")
    
    # Fetch summary data
    articles = fetch_data("articles", limit=100)
    cves = fetch_data("cves", limit=100)
    iocs = fetch_data("iocs", limit=100)
    india_alerts = fetch_data("india_cyber_alerts", limit=50)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Articles", len(articles))
    with col2:
        st.metric("Total CVEs", len(cves))
    with col3:
        st.metric("IOCs Collected", len(iocs))
    with col4:
        st.metric("India Alerts", len(india_alerts))
    
    # Charts
    if cves:
        st.subheader("CVEs by Severity")
        severity_counts = Counter(c.get("severity", "UNKNOWN") for c in cves)
        severity_df = pd.DataFrame(
            severity_counts.items(), 
            columns=["Severity", "Count"]
        )
        fig = px.bar(severity_df, x="Severity", y="Count", 
                     color="Severity",
                     color_discrete_map={
                         "CRITICAL": "#c0392b", "HIGH": "#e67e22",
                         "MEDIUM": "#f39c12", "LOW": "#3498db"
                     })
        st.plotly_chart(fig, use_container_width=True)
    
    if articles:
        st.subheader("Articles by Source")
        source_counts = Counter(a.get("source", "Unknown") for a in articles)
        source_df = pd.DataFrame(
            source_counts.most_common(10),
            columns=["Source", "Count"]
        )
        fig = px.pie(source_df, values="Count", names="Source")
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent activity
    st.subheader("Recent Activity")
    recent = articles[:10] + cves[:10]
    for item in sorted(recent, key=lambda x: x.get("created_at", ""), reverse=True)[:10]:
        title = item.get("title") or item.get("cve_id") or item.get("ioc_value", "")
        source = item.get("source", "Unknown")
        st.write(f"- **{title}** ({source})")


# =============================================================================
# CVEs Page
# =============================================================================

elif page == "CVEs":
    st.header("🔴 CVE Vulnerabilities")
    
    cves = fetch_data("cves", limit=200)
    
    if cves:
        df = pd.DataFrame(cves)
        
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH"]
            )
        with col2:
            if st.checkbox("Exploit Available Only"):
                df = df[df["exploit_available"] == True]
        
        if severity_filter:
            df = df[df["severity"].isin(severity_filter)]
        
        # Display
        for _, cve in df.head(50).iterrows():
            with st.expander(f"{cve.get('cve_id', 'Unknown')} - CVSS: {cve.get('cvss_v3_score', 'N/A')} [{cve.get('severity', 'N/A')}]"):
                st.write(f"**Description:** {cve.get('description', 'No description')[:500]}")
                if cve.get("ai_summary"):
                    st.write(f"**AI Analysis:** {cve['ai_summary']}")
                if cve.get("exploit_available"):
                    st.error("⚠️ Exploit Available in the Wild")
                if cve.get("affected_vendors"):
                    st.write(f"**Affected Vendors:** {', '.join(cve['affected_vendors'][:10])}")
    else:
        st.info("No CVEs loaded. Run data collection first.")


# =============================================================================
# Articles Page
# =============================================================================

elif page == "Articles":
    st.header("📰 Cybersecurity Articles")
    
    articles = fetch_data("articles", limit=100)
    
    if articles:
        # Filters
        filter_col, search_col = st.columns([1, 2])
        with filter_col:
            category_filter = st.multiselect(
                "Category",
                options=list(set(a.get("threat_category", "Uncategorized") for a in articles)),
            )
        with search_col:
            search = st.text_input("Search articles", "")
        
        for article in articles[:50]:
            if category_filter and article.get("threat_category") not in category_filter:
                continue
            if search and search.lower() not in (article.get("title", "") + " " + (article.get("cleaned_content") or "")).lower():
                continue
            
            with st.expander(f"[{article.get('severity', 'INFO')}] {article.get('title', 'Untitled')}"):
                st.write(f"**Source:** {article.get('source', 'Unknown')}")
                st.write(f"**Published:** {article.get('published_date', 'Unknown')}")
                st.write(f"**Category:** {article.get('threat_category', 'Uncategorized')}")
                if article.get("summary"):
                    st.write(f"**AI Summary:** {article['summary']}")
                if article.get("cve_ids"):
                    st.write(f"**CVE IDs:** {', '.join(article['cve_ids'])}")
                if article.get("tags"):
                    st.write(f"**Tags:** {', '.join(article['tags'])}")
                if article.get("url"):
                    st.markdown(f"[Read Full Article]({article['url']})")
    else:
        st.info("No articles loaded. Run data collection first.")


# =============================================================================
# India Threat Intel Page
# =============================================================================

elif page == "India Threat Intel":
    st.header("🇮🇳 India Cyber Threat Intelligence")
    
    alerts = fetch_data("india_cyber_alerts", limit=50)
    scams = fetch_data("india_scam_tracking", limit=50)
    
    # Alerts section
    st.subheader("India Cyber Alerts")
    if alerts:
        for alert in alerts:
            severity = alert.get("severity", "MEDIUM")
            emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "ℹ️")
            with st.expander(f"{emoji} [{severity}] {alert.get('title', 'Unknown Alert')}"):
                st.write(f"**Source:** {alert.get('source', 'Unknown')}")
                st.write(f"**Type:** {alert.get('alert_type', 'General')}")
                st.write(f"**Description:** {alert.get('description', '')[:500]}")
                if alert.get("targeted_banks"):
                    st.warning(f"**Targeted Banks:** {', '.join(alert['targeted_banks'])}")
                if alert.get("upi_apps"):
                    st.warning(f"**UPI Apps Targeted:** {', '.join(alert['upi_apps'])}")
    else:
        st.info("No India-specific alerts yet.")
    
    # Scams section
    st.subheader("Indian Scam Campaigns")
    if scams:
        scam_df = pd.DataFrame(scams)
        st.dataframe(scam_df[["scam_name", "scam_type", "is_active", "incidents_count"]], use_container_width=True)
    else:
        st.info("No scam data yet.")


# =============================================================================
# IOCs Page
# =============================================================================

elif page == "IOCs":
    st.header("🔍 Indicators of Compromise")
    
    iocs = fetch_data("iocs", limit=200)
    
    if iocs:
        df = pd.DataFrame(iocs)
        
        # Type filter
        ioc_types = df["ioc_type"].unique() if "ioc_type" in df.columns else []
        selected_type = st.multiselect("IOC Type", options=ioc_types, default=[])
        
        if selected_type:
            df = df[df["ioc_type"].isin(selected_type)]
        
        # Display as table
        display_cols = ["ioc_value", "ioc_type", "threat_type", "source", "confidence"]
        display_cols = [c for c in display_cols if c in df.columns]
        
        st.dataframe(df[display_cols].head(100), use_container_width=True)
        
        # Stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Unique IPs", len(df[df["ioc_type"] == "ip"]) if "ioc_type" in df.columns else 0)
        with col2:
            st.metric("Domains", len(df[df["ioc_type"] == "domain"]) if "ioc_type" in df.columns else 0)
        with col3:
            st.metric("Hashes & URLs", len(df[df["ioc_type"].isin(["md5", "sha1", "sha256", "url"])]) if "ioc_type" in df.columns else 0)
    else:
        st.info("No IOCs collected yet.")


# =============================================================================
# Reports Page
# =============================================================================

elif page == "Reports":
    st.header("📑 Generated Reports")
    
    reports = fetch_data("reports", limit=50)
    
    if reports:
        report_df = pd.DataFrame(reports)
        
        # Group by type
        if "report_type" in report_df.columns:
            report_types = report_df["report_type"].unique()
            for rtype in report_types:
                st.subbutton_style = f"### {rtype.title()} Reports" if hasattr(st, "subbutton_style") else None
                st.markdown(f"### {rtype.title()} Reports")
                type_reports = report_df[report_df["report_type"] == rtype]
                for _, r in type_reports.iterrows():
                    st.write(f"- **{r.get('title', 'Report')}** ({r.get('report_date', '')})")
                    if r.get("summary"):
                        st.write(f"  {r['summary'][:200]}...")
    else:
        st.info("No reports generated yet. Reports are generated automatically on schedule.")

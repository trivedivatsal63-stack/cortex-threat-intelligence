import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import feedparser
import requests

from cortex.config.settings import settings


def _fetch(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 30) -> str | None:
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        r.raise_for_status()
        return r.text
    except requests.RequestException as e:
        print(f"[feed_collector] Request failed: {url} — {e}")
        return None


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _safe_date(val: str) -> str:
    return val if val else datetime.now(timezone.utc).isoformat()


def collect_nvd() -> list[dict[str, Any]]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    since = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.000")
    until = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {"pubStartDate": since, "pubEndDate": until, "resultsPerPage": 50}
    headers = {"User-Agent": "Mozilla/5.0"}
    raw = _fetch(url, params=params, headers=headers)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    items: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_data = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
        )
        score = cvss_data.get("baseScore")
        severity = _severity_from_cvss(score)
        published = cve.get("published", "")
        items.append({
            "title": cve_id,
            "description": description[:2000],
            "source": "NVD",
            "severity": severity,
            "published_date": _safe_date(published),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "raw_data": json.dumps(cve),
        })
        time.sleep(0.6)
    return items


def collect_cisa_kev() -> list[dict[str, Any]]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    raw = _fetch(url)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    items: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        items.append({
            "title": cve_id,
            "description": vuln.get("shortDescription", "")[:2000],
            "source": "CISA_KEV",
            "severity": "CRITICAL",
            "published_date": _safe_date(vuln.get("dateAdded", "")),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "raw_data": json.dumps(vuln),
        })
    return items


def collect_hacker_news() -> list[dict[str, Any]]:
    url = "https://thehackernews.com/feeds/posts/default"
    raw = _fetch(url)
    if not raw:
        return []

    feed = feedparser.parse(raw)
    items: list[dict[str, Any]] = []
    for entry in feed.entries[:20]:
        title = getattr(entry, "title", "")
        if not title:
            continue
        link = getattr(entry, "link", "")
        desc = getattr(entry, "summary", getattr(entry, "description", ""))[:2000]
        published = ""
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
        items.append({
            "title": title,
            "description": desc,
            "source": "TheHackerNews",
            "severity": "UNKNOWN",
            "published_date": _safe_date(published),
            "url": link,
            "raw_data": json.dumps(entry, default=str),
        })
    return items


def _parse_rss_entries(raw: str, source: str, severity: str = "HIGH") -> list[dict[str, Any]]:
    feed = feedparser.parse(raw)
    items: list[dict[str, Any]] = []
    for entry in feed.entries[:20]:
        title = getattr(entry, "title", "")
        if not title:
            continue
        link = getattr(entry, "link", "")
        desc = getattr(entry, "summary", getattr(entry, "description", ""))[:2000]
        published = ""
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
        items.append({
            "title": title,
            "description": desc,
            "source": source,
            "severity": severity,
            "published_date": _safe_date(published),
            "url": link,
            "raw_data": json.dumps(entry, default=str),
        })
    return items


def collect_ncsc_uk() -> list[dict[str, Any]]:
    url = "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
    raw = _fetch(url, headers={"User-Agent": "Mozilla/5.0"})
    if not raw:
        print("[ncsc_uk] Failed to fetch RSS feed")
        return []
    items = _parse_rss_entries(raw, source="NCSC_UK", severity="HIGH")
    print(f"[ncsc_uk] Collected {len(items)} items")
    return items


def collect_jpcert() -> list[dict[str, Any]]:
    url = "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"
    raw = _fetch(url)
    if not raw:
        print("[jpcert] Failed to fetch RSS feed")
        return []
    items = _parse_rss_entries(raw, source="JPCERT", severity="HIGH")
    print(f"[jpcert] Collected {len(items)} items")
    return items


def collect_alienvault_otx() -> list[dict[str, Any]]:
    api_key = settings.otx_api_key
    if not api_key:
        print("[feed_collector] OTX_API_KEY not set, skipping AlienVault OTX")
        return []

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    raw = _fetch(url, headers={"X-OTX-API-Key": api_key})
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    items: list[dict[str, Any]] = []
    for pulse in data.get("results", [])[:20]:
        title = pulse.get("name", "")
        if not title:
            continue
        desc = pulse.get("description", "")[:2000]
        severity_raw = pulse.get("tlp", "amber")
        severity = "HIGH" if severity_raw == "red" else "MEDIUM" if severity_raw == "amber" else "LOW"
        created = pulse.get("created", "")
        items.append({
            "title": title,
            "description": desc,
            "source": "AlienVault_OTX",
            "severity": severity,
            "published_date": _safe_date(created),
            "url": pulse.get("url", ""),
            "raw_data": json.dumps(pulse, default=str),
        })
    return items


def collect_all() -> dict[str, list[dict[str, Any]]]:
    print("[feed_collector] Starting collection from all sources...")
    results = {
        "nvd": collect_nvd(),
        "cisa_kev": collect_cisa_kev(),
        "hacker_news": collect_hacker_news(),
        "ncsc_uk": collect_ncsc_uk(),
        "jpcert": collect_jpcert(),
        "alienvault_otx": collect_alienvault_otx(),
    }
    total = sum(len(v) for v in results.values())
    print(f"[feed_collector] Collection complete: {total} items across {len(results)} sources")
    return results

# CORTEX — Cyber Threat Intelligence Platform

AI-powered threat intelligence that collects, scores, and visualizes cyber threats from 5 sources.

## How It Works

**3-step pipeline:**

1. **Collect** — `python main.py --collect` fetches threats from NVD CVE API, CISA KEV, TheHackerNews RSS, CERT-In RSS, and AlienVault OTX. Saves to Supabase (PostgreSQL) with dedup by URL.

2. **Score** — `python main.py --score` runs Groq AI (`llama-3.3-70b-versatile`) on unscored CRITICAL/HIGH threats. Generates: risk score (1-10), plain-language summary, attack type, affected systems, action required, India relevance.

3. **View** — `cd cortex-web && npm run dev` starts a Next.js dashboard showing all threats with filters (severity, source), pagination, AI-analysis badges, and click-to-expand modals.

Run all three: `python main.py` (runs collect → score → summary).

## Project Layout

```
├── cortex/              # Python backend
│   ├── collectors/      # feed_collector.py — 5 source collectors
│   ├── database/        # supabase_client.py — batch upsert, queries
│   ├── ai/              # scorer.py — Groq AI analysis
│   ├── config/          # settings.py — env vars
│   └── alerts/          # placeholder
├── cortex-web/          # Next.js 16 dashboard (TypeScript, Tailwind)
├── main.py              # CLI entry point
└── .github/workflows/   # pipeline.yml — optional cron automation
```

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env   # add your keys
python main.py          # collect + score + summary
cd cortex-web && npm install && npm run dev
```

### Required API Keys
- Supabase (URL + service_role key)
- Groq AI (free at console.groq.com)
- OTX API Key (optional, for AlienVault)

### Dashboard Features
- Dark-themed glassmorphism UI
- Stat cards with animated counters
- Filter by severity (Critical/High/Medium/Low) and source
- Paginated threat cards with severity-colored left borders
- Click-to-expand modal with full AI analysis or pending state
- Auto-refresh every 5 minutes
- Live indicator + update timestamp

## Data Sources

| Source | Type | Content |
|--------|------|---------|
| NVD CVE API | JSON API | All published CVEs with CVSS scores |
| CISA KEV | JSON Feed | Known exploited vulnerabilities |
| TheHackerNews | RSS Feed | Cybersecurity news articles |
| CERT-In | RSS Feed | Indian government security advisories |
| AlienVault OTX | REST API | Community threat pulses |

## Automation

GitHub Actions workflow runs every 6 hours (`python main.py`). Trigger manually from Actions tab.

# 🛡️ Cyber Threat Intelligence Platform

An **AI-powered, cloud-native Cybersecurity Threat Intelligence Platform** that continuously collects, analyzes, and alerts on cyber threats from **30+ global and Indian sources** — fully automated with **GitHub Actions**, powered by **Groq AI**, and stored in **Supabase PostgreSQL**.

> **🇮🇳 Includes dedicated India Cyber Threat Intelligence Module** tracking UPI fraud, Aadhaar scams, CERT-In advisories, Indian banking malware, and more.

---

## 🎯 Core Capabilities

| Feature | Status |
|---------|--------|
| **Automated Data Collection** from 30+ sources | ✅ |
| **AI-Powered Analysis** via Groq API | ✅ |
| **CVE Tracking** with severity scoring | ✅ |
| **IOC Extraction** (IPs, domains, hashes, URLs) | ✅ |
| **🇮🇳 India Threat Intelligence** module | ✅ |
| **Telegram & Email Alerts** for critical threats | ✅ |
| **Daily/Weekly Reports** in Markdown, HTML, JSON | ✅ |
| **REST API** for integration | ✅ |
| **Streamlit Dashboard** for visualization | ✅ |
| **pgvector-ready** for RAG/embeddings | ✅ |
| **24/7 Automation** via GitHub Actions | ✅ |

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GITHUB ACTIONS (Cron)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ scrape.yml│  │process.yml│  │report.yml│  │alerts.yml│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
└───────┼──────────────┼──────────────┼──────────────┼────────┘
        │              │              │              │
┌───────▼──────────────▼──────────────▼──────────────▼────────┐
│                    MAIN PIPELINE (main.py)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ COLLECT  │→ │ PROCESS  │→ │ AI ENRICH│→ │ REPORT   │   │
│  │ (8 hours)│  │ (dedup)  │  │ (Groq)   │  │ (Jinja2) │   │
│  └──────────┘  └──────────┘  └──────────┘  └────┬─────┘   │
│                                      ┌──────────┐ │        │
│                                      │  ALERTS  │◄┘        │
│                                      │ (TG+Mail)│          │
│                                      └──────────┘          │
└─────────────────────────────────────────────────────────────┘
        │              │              │
┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
│  SUPABASE    │ │  FASTAPI    │ │  STREAMLIT  │
│  PostgreSQL  │ │  REST API   │ │  DASHBOARD  │
│  (pgvector)  │ │  (port 8000)│ │  (port 8501)│
└──────────────┘ └─────────────┘ └─────────────┘
```

### Data Flow

1. **COLLECT** → RSS feeds, REST APIs, and web sources fetched every 6 hours via GitHub Actions
2. **PROCESS** → HTML cleaned, CVE IDs extracted, IOCs parsed, deduplication applied
3. **AI ENRICH** → Groq API summarizes, classifies, and extracts threat intelligence
4. **STORE** → All data stored in Supabase PostgreSQL with dedup hashes
5. **REPORT** → Jinja2 templates generate daily, weekly, and India-specific reports
6. **ALERT** → Critical threats sent via Telegram + Email immediately

---

## 📡 Data Sources (30+)

### Global Cybersecurity Sources
| Category | Sources |
|----------|---------|
| **Official** | NVD CVE API, CISA KEV, CISA Alerts, MITRE ATT&CK, GitHub Security Advisories |
| **News** | The Hacker News, KrebsOnSecurity, BleepingComputer, Dark Reading, SecurityWeek, Malwarebytes, Cisco Talos, Unit 42, CrowdStrike, SentinelOne, Microsoft Security |
| **Threat Feeds** | AlienVault OTX, AbuseIPDB, URLHaus, MalwareBazaar, OpenPhish, PhishTank |
| **Exploits** | Exploit-DB, Packet Storm Security |

### 🇮🇳 Indian Sources
| Category | Sources |
|----------|---------|
| **Government** | CERT-In Advisories & Alerts, DSCI |
| **News** | Medianama Cybersecurity, Indian Express Cybersecurity, Times of India Cybercrime, The Hindu Cybersecurity |
| **Scam Tracking** | UPI fraud, Fake KYC, SIM swap, Aadhaar scams, Trading app scams, Telecom fraud |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Supabase account (free tier: [supabase.com](https://supabase.com))
- Groq API key (free: [console.groq.com](https://console.groq.com))
- GitHub account (for automation)
- Telegram bot (optional, for alerts)

### 1. Local Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/cyber-threat-intel.git
cd cyber-threat-intel

# Make setup script executable and run
chmod +x setup.sh
./setup.sh

# Or manually:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys (see below)
```

### 2. Configure Environment

Edit `.env` with your credentials:

```ini
# REQUIRED: Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
DATABASE_URL=postgresql://postgres:password@host:6543/postgres

# REQUIRED: Groq AI
GROQ_API_KEY=gsk_your-groq-api-key

# OPTIONAL: Telegram Alerts
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# OPTIONAL: Email Alerts
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=recipient@example.com
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-gmail-app-password
```

### 3. Initialize Database

Open your Supabase project's SQL Editor and run the contents of `database/schema.sql`.
This creates all tables, indexes, and triggers.

### 4. Run the Pipeline

```bash
# Full pipeline
python main.py

# Or run specific stages
python main.py --collect-only    # Only collect data
python main.py --report-only     # Only generate reports
```

### 5. Start the API & Dashboard

```bash
# REST API
uvicorn api.server:app --host 0.0.0.0 --port 8000

# Dashboard (in another terminal)
streamlit run dashboard/app.py

# Access:
# API: http://localhost:8000
# Dashboard: http://localhost:8501
# API Docs: http://localhost:8000/docs
```

### 6. Docker Deployment

```bash
docker-compose up -d
```

---

## 🤖 GitHub Actions Automation (24/7 Operation)

The platform runs **entirely on GitHub's infrastructure** — your laptop can be OFF.

### Setup GitHub Secrets
Go to your repository → Settings → Secrets and variables → Actions → Add these secrets:

| Secret | Description |
|--------|-------------|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Your Supabase anon/public key |
| `DATABASE_URL` | Your Supabase PostgreSQL connection string |
| `GROQ_API_KEY` | Your Groq API key |
| `TELEGRAM_BOT_TOKEN` | Your Telegram bot token |
| `TELEGRAM_CHAT_ID` | Your Telegram chat ID |
| `EMAIL_FROM` | Sender email address |
| `EMAIL_TO` | Recipient email address |
| `SMTP_USERNAME` | Gmail SMTP username |
| `SMTP_PASSWORD` | Gmail App Password |

### Workflow Schedule
| Workflow | Schedule | Description |
|----------|----------|-------------|
| `scrape.yml` | Every 6 hours | Data collection from all sources |
| `process.yml` | Every 8 hours | AI processing, storage, alerts |
| `report.yml` | Daily 07:00 UTC | Generate daily reports |
| `weekly-digest.yml` | Sundays 09:00 UTC | Weekly intelligence digest |
| `alerts.yml` | After processing | Send critical alerts |

---

## 📊 Output Examples

### Report Types
| Report | Frequency | Content |
|--------|-----------|---------|
| **Daily Threat Report** | Daily | All CVEs, articles, IOCs, India alerts |
| **Weekly Intelligence Digest** | Weekly | Trends, statistics, predictions |
| **🇮🇳 India Cyber Digest** | Daily | India-specific threats and scams |
| **Critical Alerts** | Real-time | CRITICAL/HIGH severity threats |

### Example Daily Report Sections
- Executive Summary (AI-generated)
- Threat Statistics
- Critical CVEs (CVSS >= 9.0)
- High Priority Threats
- India Cyber Threat Intelligence
- Top Threat Actors & Malware
- Trending Attack Vectors
- IOCs Collected
- Recommendations

---

## 📁 Project Structure

```
cyber-threat-intel/
│
├── .github/workflows/          # GitHub Actions automation
│   ├── scrape.yml              # Data collection (6-hour cron)
│   ├── process.yml             # AI processing (8-hour cron)
│   ├── report.yml              # Report generation (daily)
│   ├── alerts.yml              # Alert dispatch
│   └── weekly-digest.yml       # Weekly digest (Sundays)
│
├── collectors/                 # Data ingestion layer
│   ├── base.py                 # Base collector class
│   ├── rss_collector.py        # RSS/Atom feed parser
│   ├── nvd_collector.py        # NVD CVE API client
│   ├── cisa_collector.py       # CISA KEV catalog
│   ├── api_collector.py        # Generic API collector
│   ├── india_collector.py      # 🇮🇳 India-specific sources
│   └── orchestrator.py         # Collection coordinator
│
├── processors/                 # Data processing pipeline
│   ├── article_processor.py    # Article normalization & enrichment
│   ├── cve_processor.py        # CVE analysis & prioritization
│   ├── ioc_processor.py        # IOC extraction & validation
│   └── india_processor.py      # 🇮🇳 India threat processing
│
├── ai_engine/                  # AI/ML integration
│   ├── groq_client.py          # Groq API client
│   └── prompts.py              # Centralized AI prompts
│
├── database/                   # Database layer
│   ├── schema.sql              # Full PostgreSQL schema
│   ├── connection.py           # SQLAlchemy connection manager
│   ├── models.py               # Data transfer objects
│   └── supabase_client.py      # Supabase REST client
│
├── reports/                    # Report generation
│   └── generator.py            # Jinja2 report engine
│
├── templates/                  # Jinja2 templates
│   ├── daily_report.md.j2      # Daily report template
│   ├── weekly_digest.md.j2     # Weekly digest template
│   ├── india_digest.md.j2      # 🇮🇳 India digest template
│   └── alert_template.md.j2    # Alert message template
│
├── alerts/                     # Notification system
│   ├── telegram_bot.py         # Telegram integration
│   ├── email_alerts.py         # Gmail SMTP integration
│   └── alert_manager.py        # Alert policy engine
│
├── api/                        # REST API
│   └── server.py               # FastAPI application
│
├── dashboard/                  # Visualization
│   └── app.py                  # Streamlit dashboard
│
├── config/                     # Configuration
│   ├── settings.py             # Central settings
│   └── sources.py              # All data source definitions
│
├── utils/                      # Utilities
│   ├── logging.py              # Loguru logging setup
│   ├── retry.py                # Tenacity retry decorators
│   ├── rate_limiter.py         # Async rate limiter
│   ├── dedup.py                # Deduplication engine
│   └── normalizer.py           # Text/date normalization
│
├── main.py                     # Orchestration pipeline
├── generate_weekly_digest.py   # Weekly digest script
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker image
├── docker-compose.yml          # Multi-service deployment
├── setup.sh                    # Setup script
├── .env.example                # Environment template
└── README.md                   # This file
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_collectors.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

---

## 🛡️ Future Evolution Paths

This platform is designed to evolve into:

| Evolution Path | Description |
|----------------|-------------|
| **AI SOC Assistant** | Real-time threat analysis with chatbot interface |
| **Threat Intelligence SaaS** | Multi-tenant platform with API access |
| **SIEM-Style Analytics** | Correlation rules, dashboards, alerting |
| **Cybersecurity Research Platform** | Historical analysis, trend prediction |
| **🇮🇳 Indian Cybercrime Platform** | India-focused threat monitoring |
| **RAG Cybersecurity Assistant** | Query your threat database with natural language |
| **Threat Hunting Platform** | Proactive IOC hunting and detection |

### For RAG/LLM Integration
- `pgvector` extension is included in schema
- Embeddings table is ready for vector storage
- Replace the embedding dimension in `schema.sql` based on your model
- Use LangChain/LlamaIndex for RAG chains

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Database connection fails | Verify `DATABASE_URL` in `.env` |
| Groq API errors | Check `GROQ_API_KEY` is valid |
| No data collected | Check internet access and API rate limits |
| Telegram alerts not sending | Verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` |
| Email not sending | Use [Gmail App Password](https://myaccount.google.com/apppasswords) (not your regular password) |

### Logs
Check the `logs/` directory for detailed execution logs:
- `cyber_intel_YYYY-MM-DD.log` — All messages
- `errors_YYYY-MM-DD.log` — Error-only messages

---

## 🤝 Contributing

Contributions are welcome! Areas for contribution:
- Add new data sources
- Improve AI prompts
- Enhance India threat detection
- Add new report templates
- Improve dashboard visualizations
- Add vector embeddings for RAG

---

## 📄 License

MIT License. See `LICENSE` for details.

---

## ⚡ Performance Notes

- **AI API Costs**: ~50-100 Groq API calls per run (~$0.02-0.05 at Groq prices)
- **Storage**: ~50-100 MB/month on Supabase free tier
- **GitHub Actions**: 2000 minutes/month free (more than enough for 4 runs/day)
- **Collection Time**: ~5-15 minutes per full collection run

---

*Built with ❤️ for the global cybersecurity community and 🇮🇳 India's cyber resilience.*

-- =============================================================================
-- Cyber Threat Intelligence Platform - Database Schema
-- Target: Supabase PostgreSQL with pgvector support
-- 
-- This schema is the foundation of the entire platform.
-- It's designed for:
--   - Efficient deduplication via hash indexes
--   - Fast text search with GIN indexes
--   - Future vector similarity search with pgvector
--   - Scalable time-series queries
-- =============================================================================

-- Enable pgvector extension for future RAG/embeddings support
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- ARTICLES TABLE
-- Stores cybersecurity news articles from all global sources
-- =============================================================================
CREATE TABLE IF NOT EXISTS articles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    author VARCHAR(255),
    published_date TIMESTAMPTZ,
    scraped_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    article_content TEXT,
    cleaned_content TEXT,
    summary TEXT,
    tags TEXT[],
    cve_ids TEXT[],
    threat_category VARCHAR(100),
    severity VARCHAR(20),
    is_india_related BOOLEAN DEFAULT FALSE,
    india_keywords TEXT[],
    ai_processed BOOLEAN DEFAULT FALSE,
    ai_processed_at TIMESTAMPTZ,
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_articles_severity ON articles(severity);
CREATE INDEX IF NOT EXISTS idx_articles_threat_category ON articles(threat_category);
CREATE INDEX IF NOT EXISTS idx_articles_india ON articles(is_india_related) WHERE is_india_related = TRUE;
CREATE INDEX IF NOT EXISTS idx_articles_content_hash ON articles(content_hash);
CREATE INDEX IF NOT EXISTS idx_articles_tags ON articles USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_articles_cve_ids ON articles USING GIN(cve_ids);
CREATE INDEX IF NOT EXISTS idx_articles_ai_processed ON articles(ai_processed) WHERE ai_processed = FALSE;

-- Full text search index
CREATE INDEX IF NOT EXISTS idx_articles_fts ON articles USING GIN(
    to_tsvector('english', coalesce(title, '') || ' ' || coalesce(cleaned_content, ''))
);


-- =============================================================================
-- CVES TABLE
-- CVE vulnerability tracking with CVSS scores and exploit info
-- =============================================================================
CREATE TABLE IF NOT EXISTS cves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    cvss_v2_score DECIMAL(3,1),
    cvss_v3_score DECIMAL(3,1),
    severity VARCHAR(20),
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_references TEXT[],
    affected_vendors TEXT[],
    affected_products TEXT[],
    attack_vector VARCHAR(100),
    published_date TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    
    -- MITRE ATT&CK mappings
    mitre_techniques TEXT[],
    mitre_tactics TEXT[],
    
    -- AI enrichment
    ai_summary TEXT,
    ai_classification VARCHAR(100),
    ai_processed BOOLEAN DEFAULT FALSE,
    ai_processed_at TIMESTAMPTZ,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    cve_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_exploit ON cves(exploit_available) WHERE exploit_available = TRUE;
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_vendors ON cves USING GIN(affected_vendors);


-- =============================================================================
-- IOCS TABLE (Indicators of Compromise)
-- Stores IPs, domains, hashes, and malicious URLs
-- =============================================================================
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_value TEXT NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,  -- ip, domain, md5, sha1, sha256, url
    threat_type VARCHAR(100),
    source TEXT,
    source_url TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reference_count INTEGER DEFAULT 1,
    tags TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    confidence DECIMAL(3,2) DEFAULT 0.5,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    ioc_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_threat ON iocs(threat_type);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_iocs_ioc_hash ON iocs(ioc_hash);


-- =============================================================================
-- INDIA CYBER ALERTS TABLE
-- India-specific cybersecurity alerts and advisories
-- =============================================================================
CREATE TABLE IF NOT EXISTS india_cyber_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    url TEXT,
    source VARCHAR(100) NOT NULL,
    alert_type VARCHAR(100),  -- cert-in, rbi, meity, cybercrime
    description TEXT,
    severity VARCHAR(20),
    affected_sectors TEXT[],
    affected_states TEXT[],
    targeted_banks TEXT[],
    published_date TIMESTAMPTZ,
    
    -- Scam/attack details
    scam_type VARCHAR(100),
    scam_amount VARCHAR(100),
    upi_apps TEXT[],
    
    -- AI enrichment
    ai_summary TEXT,
    ai_classification VARCHAR(100),
    ai_processed BOOLEAN DEFAULT FALSE,
    ai_processed_at TIMESTAMPTZ,
    
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_india_alerts_type ON india_cyber_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_india_alerts_severity ON india_cyber_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_india_alerts_scam ON india_cyber_alerts(scam_type);
CREATE INDEX IF NOT EXISTS idx_india_alerts_banks ON india_cyber_alerts USING GIN(targeted_banks);


-- =============================================================================
-- INDIA SCAM TRACKING TABLE
-- Tracks Indian-specific scam campaigns (UPI fraud, fake KYC, etc.)
-- =============================================================================
CREATE TABLE IF NOT EXISTS india_scam_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scam_name VARCHAR(255),
    scam_type VARCHAR(100),  -- upi-fraud, fake-kyc, sim-swap, trading-app, etc.
    description TEXT,
    platform TEXT[],  -- upi apps, telecom providers, etc.
    targeted_banks TEXT[],
    targeted_regions TEXT[],
    reported_amount VARCHAR(100),
    indicators TEXT[],  -- scam phone numbers, URLs, etc.
    first_reported TIMESTAMPTZ,
    last_reported TIMESTAMPTZ,
    incidents_count INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    
    ai_summary TEXT,
    ai_processed BOOLEAN DEFAULT FALSE,
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scam_type ON india_scam_tracking(scam_type);
CREATE INDEX IF NOT EXISTS idx_scam_active ON india_scam_tracking(is_active) WHERE is_active = TRUE;


-- =============================================================================
-- MALWARE FAMILIES TABLE
-- Tracks known malware families with relationship data
-- =============================================================================
CREATE TABLE IF NOT EXISTS malware_families (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    aliases TEXT[],
    malware_type VARCHAR(100),
    description TEXT,
    capabilities TEXT[],
    targeted_platforms TEXT[],
    targeted_sectors TEXT[],
    associated_threat_actors TEXT[],
    mitre_techniques TEXT[],
    ioc_references TEXT[],
    first_seen TIMESTAMPTZ,
    last_activity TIMESTAMPTZ,
    
    ai_summary TEXT,
    ai_processed BOOLEAN DEFAULT FALSE,
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =============================================================================
-- THREAT ACTORS TABLE
-- Tracks known APT groups and cybercriminal organizations
-- =============================================================================
CREATE TABLE IF NOT EXISTS threat_actors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    aliases TEXT[],
    motivation VARCHAR(255),
    targeted_sectors TEXT[],
    targeted_regions TEXT[],
    associated_malware TEXT[],
    active_techniques TEXT[],
    first_observed TIMESTAMPTZ,
    last_observed TIMESTAMPTZ,
    attribution TEXT,
    profile TEXT,
    
    ai_summary TEXT,
    ai_processed BOOLEAN DEFAULT FALSE,
    content_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =============================================================================
-- REPORTS TABLE
-- Stores generated reports (daily, weekly, etc.)
-- =============================================================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_type VARCHAR(50) NOT NULL,  -- daily, weekly, critical, india, banking
    title TEXT NOT NULL,
    summary TEXT,
    content_markdown TEXT,
    content_html TEXT,
    content_json JSONB,
    report_date DATE NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Statistics for the report period
    stats JSONB DEFAULT '{}'::jsonb,
    top_threats JSONB DEFAULT '[]'::jsonb,
    critical_cves TEXT[],
    ransomware_mentions INTEGER DEFAULT 0,
    phishing_mentions INTEGER DEFAULT 0,
    india_incidents INTEGER DEFAULT 0,
    
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_date ON reports(report_date DESC);


-- =============================================================================
-- LOGS TABLE
-- Centralized operation logging for debugging and monitoring
-- =============================================================================
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    level VARCHAR(10) NOT NULL,
    module VARCHAR(100),
    function VARCHAR(100),
    message TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_module ON logs(module);
CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);


-- =============================================================================
-- VECTOR EMBEDDINGS TABLE (for pgvector RAG support)
-- Stores vector embeddings of articles for semantic search
-- =============================================================================
CREATE TABLE IF NOT EXISTS embeddings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_table VARCHAR(50) NOT NULL,
    source_id UUID NOT NULL,
    content_text TEXT NOT NULL,
    embedding vector(1536),  -- OpenAI ada-002 dimension; adjust for other models
    model VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_embeddings_source ON embeddings(source_table, source_id);
-- Vector index (uncomment when pgvector is fully enabled)
-- CREATE INDEX IF NOT EXISTS idx_embeddings_vector ON embeddings USING ivfflat (embedding vector_cosine_ops);


-- =============================================================================
-- HELPER FUNCTION: Update updated_at timestamp
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply auto-update triggers
CREATE TRIGGER update_articles_updated_at
    BEFORE UPDATE ON articles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cves_updated_at
    BEFORE UPDATE ON cves
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_malware_updated_at
    BEFORE UPDATE ON malware_families
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_actors_updated_at
    BEFORE UPDATE ON threat_actors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

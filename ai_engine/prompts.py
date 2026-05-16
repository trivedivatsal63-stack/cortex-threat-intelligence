"""
Central repository for ALL AI prompts used in the platform.
Keeping prompts here makes them easy to maintain, version control,
and optimize without touching the client code.

WHY THIS EXISTS: Prompts are the core of AI quality. Centralizing them
allows systematic optimization, A/B testing, and ensures consistency
across the platform.
"""

# =============================================================================
# SYSTEM PROMPTS (Set the AI's role/persona)
# =============================================================================

SYSTEM_ANALYST = """You are a senior cybersecurity threat intelligence analyst at a global SOC.
Your expertise covers: threat hunting, malware analysis, vulnerability assessment,
incident response, and threat intelligence gathering.
Analyze data precisely and extract structured threat intelligence.
Always return valid JSON when requested."""

SYSTEM_CVE_ANALYST = """You are a CVE vulnerability analyst specializing in CVSS scoring,
exploitability assessment, and patch prioritization.
Provide precise, actionable vulnerability intelligence."""

SYSTEM_INDIA_ANALYST = """You are an expert in Indian cybersecurity threats.
Your focus areas: UPI fraud, Aadhaar-related scams, Indian banking malware,
SIM swap attacks, fake KYC campaigns, and Indian cybercrime trends.
Return valid JSON only."""

SYSTEM_REPORT_WRITER = """You are a senior cybersecurity reporting analyst.
Generate concise, actionable intelligence reports for CISO-level audiences.
Focus on business impact, risk, and remediation."""

# =============================================================================
# TASK PROMPTS
# =============================================================================

ARTICLE_ANALYSIS_PROMPT = """Analyze this cybersecurity article and extract key threat intelligence.

Title: {title}
Content: {content}

Extract and return JSON:
{{
  "summary": "2-3 sentence technical summary focusing on the threat",
  "threat_category": "One of: ransomware, phishing, malware, zero-day, supply-chain, cloud-attack, insider-threat, credential-theft, apt, banking-fraud, telecom-scam, upi-fraud, ddos, iot-attack, web-attack, data-breach, social-engineering, or other",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "tags": ["list of 3-7 relevant tags"],
  "cve_ids_found": ["CVE IDs mentioned"],
  "iocs_found": {{
    "ips": ["suspicious IPs"],
    "domains": ["malicious domains"],
    "urls": ["malicious URLs"],
    "hashes": ["file hashes"]
  }},
  "malware_families": ["malware families mentioned"],
  "threat_actors": ["threat actors/groups mentioned"],
  "attack_vector": "How the attack is delivered",
  "targeted_sectors": ["affected industries"],
  "key_findings": "Critical takeaway for security teams"
}}"""

CVE_ANALYSIS_PROMPT = """Analyze this CVE vulnerability:

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score}

Return JSON:
{{
  "summary": "2-3 sentence technical summary",
  "classification": "vulnerability type (RCE, XSS, SQLi, Privilege Escalation, etc.)",
  "impact_rating": "CRITICAL/HIGH/MEDIUM/LOW",
  "exploit_maturity": "Active/Proof-of-Concept/Theoretical/None",
  "mitre_attack_techniques": ["relevant MITRE ATT&CK technique IDs"],
  "patch_priority": "Immediate/This Week/This Month/Monitor",
  "recommendation": "specific remediation steps"
}}"""

INDIA_THREAT_DETECTION_PROMPT = """Analyze this content for India-specific cyber threats:

Title: {title}
Content: {content}

Return JSON:
{{
  "is_india_relevant": true/false,
  "india_threat_type": "upi-fraud/kyc-scam/sim-swap/aadhaar-scam/banking-fraud/trading-scam/telecom-scam/other/none",
  "targeted_indian_banks": ["bank names if mentioned"],
  "upi_apps_mentioned": ["Google Pay/PhonePe/Paytm/BHIM/other"],
  "scam_amount": "amount in INR if mentioned",
  "affected_regions": ["Indian cities/states mentioned"],
  "ai_summary": "India-relevant summary of the threat",
  "action_required": "specific actions for Indian users/companies"
}}"""

EXECUTIVE_SUMMARY_PROMPT = """Generate an executive summary for a cybersecurity threat intelligence report.

Report Period: {period}
Total Threats Analyzed: {total_threats}
Critical Severity Items: {critical_count}
Top Threats: {top_threats}

Data: {data}

Write a professional 2-3 paragraph executive summary covering:
1. Current threat landscape overview and severity level
2. Most critical threats requiring immediate attention
3. Key trends and patterns observed
4. Actionable recommendations for security teams

Focus on business impact and risk mitigation."""

# =============================================================================
# BATCH PROCESSING PROMPTS
# =============================================================================

BATCH_CLASSIFICATION_PROMPT = """Classify the following cybersecurity items:

Items: {items}

For each item, provide: threat_category, severity (CRITICAL/HIGH/MEDIUM/LOW), and priority_score (1-10).

Return as JSON array."""

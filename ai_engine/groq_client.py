"""
Groq API client for AI-powered threat intelligence processing.
Groq is the PRIMARY AI provider - used for:
- Article summarization
- CVE analysis and classification
- Threat categorization
- IOC extraction
- Severity scoring
- Indian fraud detection

WHY THIS EXISTS: AI transforms raw collected data into actionable intelligence.
Groq provides fast, efficient inference that's cost-effective for batch processing.
"""

import json
import asyncio
import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from loguru import logger
import httpx

from config.settings import config
from config.sources import AI_PROCESSING_PRIORITY
from utils.dedup import compute_content_hash


class GroqAIClient:
    """
    Client for the Groq API.
    Handles authentication, request formatting, response parsing,
    rate limiting, retries, and error handling.
    
    Groq provides fast inference on open-source models.
    We use mixtral-8x7b-32768 by default for its excellent
    balance of speed, quality, and context window size.
    """
    
    def __init__(self):
        self.api_key = config.groq.api_key
        self.model = config.groq.model          # Fast model (default)
        self.model_heavy = config.groq.model_heavy  # Heavy model (critical items)
        self.base_url = "https://api.groq.com/openai/v1"
        self.temperature = config.groq.temperature
        self.max_tokens = config.groq.max_tokens
        self.timeout = config.groq.timeout
        
        # Cache for AI responses to avoid reprocessing
        self._cache: Dict[str, str] = {}
        self._cache_hits = 0
        self._api_calls = 0
        
        if not self.api_key:
            logger.warning("GROQ_API_KEY not configured. AI features will be disabled.")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for Groq API requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
    
    def _get_cache_key(self, prompt: str, task_type: str) -> str:
        """Generate a cache key for a given prompt and task type."""
        return compute_content_hash(f"{task_type}|{prompt}")
    
    def _check_cache(self, prompt: str, task_type: str) -> Optional[str]:
        """Check if we have a cached response for this prompt."""
        key = self._get_cache_key(prompt, task_type)
        if key in self._cache:
            self._cache_hits += 1
            return self._cache[key]
        return None
    
    def _update_cache(self, prompt: str, task_type: str, response: str) -> None:
        """Cache an AI response."""
        key = self._get_cache_key(prompt, task_type)
        self._cache[key] = response
        # Keep cache bounded
        if len(self._cache) > 1000:
            # Remove oldest item
            self._cache.pop(next(iter(self._cache)))
    
    def _call_groq_api(self, messages: List[Dict[str, str]], 
                       response_format: Optional[Dict] = None,
                       use_heavy: bool = False) -> Optional[str]:
        """
        Make an API call to Groq with rate limit handling.
        Uses fast model by default, heavy model for critical items.
        Retries with exponential backoff on rate limits.
        """
        if not self.api_key:
            logger.error("Groq API key not configured")
            return None
        
        import time
        model = self.model_heavy if use_heavy else self.model
        
        for attempt in range(config.groq.max_retries):
            self._api_calls += 1
            
            request_body = {
                "model": model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
            
            if response_format:
                request_body["response_format"] = response_format
            
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(
                        f"{self.base_url}/chat/completions",
                        headers=self._get_headers(),
                        json=request_body,
                    )
                    
                    if response.status_code == 429:
                        # Rate limited - wait and retry
                        wait = min(2 ** attempt * 5, 60)  # 5s, 10s, 20s
                        logger.warning(
                            f"Groq rate limited (attempt {attempt+1}/{config.groq.max_retries}). "
                            f"Waiting {wait}s..."
                        )
                        time.sleep(wait)
                        continue
                    
                    response.raise_for_status()
                    result = response.json()
                    return result["choices"][0]["message"]["content"]
                    
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    wait = min(2 ** attempt * 5, 60)
                    logger.warning(f"Groq rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                logger.error(f"Groq API HTTP error {e.response.status_code}")
                if attempt == config.groq.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)
            except httpx.TimeoutException:
                logger.error("Groq API timeout")
                if attempt == config.groq.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)
            except Exception as e:
                logger.error(f"Groq API error: {e}")
                if attempt == config.groq.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)
        
        return None
    
    async def _call_groq_api_async(self, messages: List[Dict[str, str]],
                                    response_format: Optional[Dict] = None,
                                    use_heavy: bool = False) -> Optional[str]:
        """Async version of Groq API call with rate limit handling."""
        if not self.api_key:
            return None
        
        import asyncio
        model = self.model_heavy if use_heavy else self.model
        
        for attempt in range(config.groq.max_retries):
            self._api_calls += 1
            
            request_body = {
                "model": model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
            
            if response_format:
                request_body["response_format"] = response_format
            
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=self._get_headers(),
                        json=request_body,
                    )
                    
                    if response.status_code == 429:
                        wait = min(2 ** attempt * 5, 60)
                        logger.warning(f"Groq rate limited. Waiting {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    
                    response.raise_for_status()
                    result = response.json()
                    return result["choices"][0]["message"]["content"]
                    
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    wait = min(2 ** attempt * 5, 60)
                    logger.warning(f"Groq rate limited. Waiting {wait}s...")
                    await asyncio.sleep(wait)
                    continue
                logger.error(f"Groq async API error: {e}")
                return None
            except Exception as e:
                logger.error(f"Groq async API error: {e}")
                return None
        
        return None
    
    def summarize_article(self, title: str, content: str) -> Optional[Dict[str, Any]]:
        """
        Generate an AI summary and classification of a cybersecurity article.
        
        Returns: dict with summary, threat_category, severity, tags, iocs
        """
        # Truncate content to fit context window
        max_content_len = 6000
        truncated = content[:max_content_len] if len(content) > max_content_len else content
        
        prompt = f"""Analyze this cybersecurity article and extract key intelligence:

Title: {title}
Content: {truncated}

Extract and return JSON:
{{
  "summary": "2-3 sentence technical summary focusing on the threat",
  "threat_category": "One of: ransomware, phishing, malware, zero-day, supply-chain, cloud-attack, insider-threat, credential-theft, apt, banking-fraud, telecom-scam, upi-fraud, ddos, iot-attack, web-attack, data-breach, social-engineering, or other",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "tags": ["list", "of", "relevant", "tags"],
  "cve_ids_found": ["CVE IDs mentioned in the article"],
  "iocs_found": {{
    "ips": ["suspicious IPs found"],
    "domains": ["malicious domains found"],
    "urls": ["malicious URLs found"],
    "hashes": ["file hashes found"]
  }},
  "malware_families": ["malware families mentioned"],
  "threat_actors": ["threat actors/groups mentioned"],
  "attack_vector": "How the attack is delivered",
  "targeted_sectors": ["affected industries/sectors"],
  "key_findings": "Critical takeaway for security teams"
}}"""
        
        cached = self._check_cache(prompt, "summarize_article")
        if cached:
            try:
                return json.loads(cached)
            except json.JSONDecodeError:
                pass
        
        result = self._call_groq_api(
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity threat intelligence analyst. "
                               "Analyze articles precisely and extract structured threat intelligence. "
                               "Return ONLY valid JSON."
                },
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        if result:
            self._update_cache(prompt, "summarize_article", result)
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse AI response as JSON: {result[:200]}")
                return None
        
        return None
    
    def analyze_cve(self, cve_id: str, description: str, cvss_score: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Analyze a CVE and provide threat intelligence context.
        Returns enriched information about the vulnerability.
        """
        prompt = f"""Analyze this CVE vulnerability:

CVE ID: {cve_id}
Description: {description[:3000]}
CVSS Score: {cvss_score}

Return JSON:
{{
  "summary": "2-3 sentence technical summary",
  "classification": "type of vulnerability (RCE, XSS, SQLi, etc.)",
  "impact_rating": "CRITICAL/HIGH/MEDIUM/LOW",
  "exploit_maturity": "Active/Proof-of-Concept/Theoretical/None",
  "mitre_attack_techniques": ["relevant MITRE ATT&CK technique IDs"],
  "affected_vendors_found": ["vendors from description"],
  "patch_priority": "Immediate/This Week/This Month/Monitor",
  "recommendation": "specific remediation steps"
}}"""
        
        result = self._call_groq_api(
            messages=[
                {
                    "role": "system",
                    "content": "You are a CVE vulnerability analyst. Analyze CVEs precisely. Return ONLY valid JSON."
                },
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        if result:
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return None
        return None
    
    def detect_india_threat(self, title: str, content: str) -> Optional[Dict[str, Any]]:
        """
        Detect India-specific cyber threats in content.
        Identifies UPI fraud, Aadhaar scams, Indian banking threats, etc.
        """
        prompt = f"""Analyze this content for India-specific cyber threats:

Title: {title}
Content: {content[:4000]}

Return JSON:
{{
  "is_india_relevant": true/false,
  "india_threat_type": "upi-fraud/kyc-scam/sim-swap/aadhaar-scam/banking-fraud/trading-scam/other/none",
  "targeted_indian_banks": ["bank names if mentioned"],
  "upi_apps_mentioned": ["Google Pay/PhonePe/Paytm/BHIM"],
  "scam_amount": "amount if mentioned",
  "affected_regions": ["Indian cities/states mentioned"],
  "ai_summary": "India-relevant summary",
  "action_required": "specific actions for Indian users/companies"
}}"""
        
        result = self._call_groq_api(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in Indian cybersecurity threats. "
                               "Focus on UPI fraud, Aadhaar scams, Indian banking threats. "
                               "Return ONLY valid JSON."
                },
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        if result:
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return None
        return None
    
    def generate_executive_summary(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Generate an executive summary for reports.
        Used in daily/weekly intelligence digests.
        """
        prompt = f"""Generate an executive summary for a cybersecurity threat intelligence report based on these statistics:

Data: {json.dumps(data, default=str)[:3000]}

Write a professional 2-3 paragraph executive summary covering:
1. Current threat landscape overview
2. Most critical threats requiring immediate attention
3. Key trends observed
4. Actionable recommendations for security teams"""
        
        result = self._call_groq_api(
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity reporting analyst. "
                               "Generate concise, actionable executive summaries."
                },
                {"role": "user", "content": prompt}
            ]
        )
        
        return result
    
    def classify_batch(self, items: List[Dict]) -> List[Dict]:
        """
        Process a batch of items through AI.
        Prioritizes critical items for processing.
        
        WHY batching: Reduces API calls by processing multiple items
        when appropriate, though we mainly do individual calls for accuracy.
        """
        results = []
        for item in items:
            # Skip if already AI-processed
            if item.get("ai_processed"):
                results.append(item)
                continue
            
            try:
                if "cve_id" in item:
                    ai_result = self.analyze_cve(
                        item["cve_id"],
                        item.get("description", ""),
                        item.get("cvss_v3_score") or item.get("cvss_v2_score"),
                    )
                else:
                    ai_result = self.summarize_article(
                        item.get("title", ""),
                        item.get("cleaned_content") or item.get("content", ""),
                    )
                
                if ai_result:
                    item["ai_processed"] = True
                    item["ai_processed_at"] = datetime.now(timezone.utc).isoformat()
                    if "summary" in ai_result:
                        item["summary"] = ai_result["summary"]
                    if "threat_category" in ai_result:
                        item["threat_category"] = ai_result["threat_category"]
                    if "severity" in ai_result:
                        item["severity"] = ai_result["severity"]
                    if "tags" in ai_result:
                        item["tags"] = ai_result["tags"]
                
                results.append(item)
            except Exception as e:
                logger.error(f"AI processing failed for item: {e}")
                results.append(item)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get AI engine usage statistics."""
        return {
            "api_calls": self._api_calls,
            "cache_hits": self._cache_hits,
            "model": self.model,
            "cache_size": len(self._cache),
        }


# Global Groq AI client singleton
groq_client = GroqAIClient()

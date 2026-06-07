import json
import re
import time
from datetime import datetime, timezone

from groq import Groq, APIStatusError

from cortex.config.settings import settings
from cortex.database.supabase_client import get_client


def parse_groq_response(content: str) -> dict:
    import json, re

    content = re.sub(r'```json|```', '', content).strip()

    content = content.replace("'", '"')

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    result = {}

    patterns = {
        'risk_score': r'"risk_score"\s*:\s*(\d+)',
        'risk_label': r'"risk_label"\s*:\s*"([^"]+)"',
        'ai_summary': r'"ai_summary"\s*:\s*"?([^",\n}{]+)"?',
        'attack_type': r'"attack_type"\s*:\s*"?([^",\n}{]+)"?',
        'affected_systems': r'"affected_systems"\s*:\s*"([^"]+)"',
        'action_required': r'"action_required"\s*:\s*"([^"]+)"',
        'india_relevance': r'"india_relevance"\s*:\s*"([^"]+)"',
    }

    for field, pattern in patterns.items():
        match = re.search(pattern, content)
        if match:
            value = match.group(1)
            result[field] = int(value) if field == 'risk_score' else value

    if 'risk_score' in result and 'ai_summary' in result:
        return result

    raise ValueError(f"Could not parse: {content[:100]}")


def score_threats():
    if not settings.groq_api_key:
        print("[scorer] GROQ_API_KEY not set, skipping")
        return

    client = Groq(api_key=settings.groq_api_key)
    db = get_client()

    threats = []
    try:
        result = (
            db.table("threats")
            .select("*")
            .is_("ai_summary", "null")
            .in_("severity", ["CRITICAL", "HIGH"])
            .limit(100)
            .execute()
        )
        threats = result.data if result.data else []
    except Exception as e:
        print(f"[scorer] Failed to fetch unscored threats: {e}")
        return

    if not threats:
        print("[scorer] No unscored threats to process")
        return

    total = len(threats)
    scored = 0
    errors = 0

    print(f"[scorer] Scoring {total} threats...")

    for idx, threat in enumerate(threats, 1):
        title = threat.get("title", "")[:50]
        desc = threat.get("description", "")[:1500]
        source = threat.get("source", "")
        severity = threat.get("severity", "")
        url = threat.get("url", "")

        system_prompt = (
            "You are an elite cybersecurity analyst. You MUST return ONLY valid "
            "JSON with no extra text before or after. ALL string values MUST be "
            "enclosed in double quotes. Never return unquoted string values."
        )

        user_prompt = f"""Analyze this cybersecurity threat and return ONLY this JSON structure:
{{
  'risk_score': <integer 1-10>,
  'risk_label': <'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'>,
  'ai_summary': <one clear sentence explaining what this threat is and why it matters to security professionals>,
  'attack_type': <e.g. 'Remote Code Execution', 'Privilege Escalation', 'Phishing', 'DoS', 'Data Breach', etc>,
  'affected_systems': <comma separated list of affected systems/software>,
  'action_required': <one clear action: 'Patch immediately', 'Monitor and patch', 'No action needed', etc>,
  'india_relevance': <'High', 'Medium', 'Low'> based on whether this affects infrastructure commonly used in India
}}

Threat data:
Title: {title}
Description: {desc}
Source: {source}
Severity: {severity}"""

        try:
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=500,
            )

            raw = completion.choices[0].message.content
            parsed = parse_groq_response(raw)

            update_data = {
                "risk_score": parsed.get("risk_score"),
                "risk_label": parsed.get("risk_label"),
                "ai_summary": parsed.get("ai_summary", ""),
                "attack_type": parsed.get("attack_type"),
                "affected_systems": parsed.get("affected_systems"),
                "action_required": parsed.get("action_required"),
                "india_relevance": parsed.get("india_relevance"),
                "ai_scored_at": datetime.now(timezone.utc).isoformat(),
            }

            db.table("threats").update(update_data).eq("url", url).execute()
            scored += 1
            print(f"[scorer] Scored {idx}/{total}: {title}")

        except APIStatusError as e:
            if e.status_code == 429:
                print("[scorer] Rate limit reached — stopping for today. Will resume next run.")
                break
            errors += 1
            print(f"[scorer] Error {idx}/{total}: {title} — {e}")
        except Exception as e:
            errors += 1
            print(f"[scorer] Error {idx}/{total}: {title} — {e}")

        time.sleep(0.5)

    print(f"[scorer] Done: {scored} scored, {total - scored - errors} skipped, {errors} errors")

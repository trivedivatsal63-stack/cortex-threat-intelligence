from datetime import datetime, timedelta, timezone

from supabase import create_client, Client

from cortex.config.settings import settings


_client = None


def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(settings.supabase_url, settings.supabase_key)
    return _client


def save_threats(threats: list[dict]) -> int:
    if not threats:
        return 0

    client = get_client()
    batch_size = 100
    total = 0

    for i in range(0, len(threats), batch_size):
        batch = threats[i:i + batch_size]
        seen = {}
        for item in batch:
            if item.get("url"):
                seen[item["url"]] = item
        batch = list(seen.values())
        try:
            client.table("threats").upsert(batch, on_conflict="url").execute()
            total += len(batch)
        except Exception as e:
            print(f"[supabase_client] Batch upsert failed at offset {i}: {e}")

    from collections import Counter
    source_counts = Counter(t.get("source", "Unknown") for t in threats)
    print(f"[supabase_client] Upserted {total} threats across {len(threats)} items")
    for source, c in source_counts.most_common():
        print(f"  {source}: {c}")
    return total


def get_recent_threats(hours: int = 24) -> list[dict]:
    client = get_client()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    try:
        result = (
            client.table("threats")
            .select("*")
            .gte("created_at", since)
            .order("published_date", desc=True)
            .execute()
        )
        return result.data if result.data else []
    except Exception as e:
        print(f"[supabase_client] Failed to fetch recent threats: {e}")
        return []

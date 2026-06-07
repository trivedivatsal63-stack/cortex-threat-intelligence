import sys
from collections import Counter

from cortex.collectors.feed_collector import collect_all
from cortex.database.supabase_client import save_threats, get_recent_threats
from cortex.ai.scorer import score_threats


def run_collect():
    print("=" * 50)
    print("CORTEX — Threat Intelligence Collection")
    print("=" * 50)

    print("\n[*] Collecting threats from all sources...")
    raw = collect_all()

    threats = []
    for source_items in raw.values():
        threats.extend(source_items)

    print(f"\n[*] Total items collected: {len(threats)}")
    new_count = save_threats(threats)
    print(f"[*] New threats saved: {new_count}")
    return new_count


def run_summary():
    print("=" * 50)
    print("CORTEX — Threat Summary (Last 24h)")
    print("=" * 50)

    threats = get_recent_threats(24)

    if not threats:
        print("\nNo threats found in the last 24 hours.")
        return

    print(f"\nTotal threats: {len(threats)}")

    source_counts = Counter(t.get("source", "Unknown") for t in threats)
    print("\nPer source:")
    for source, count in source_counts.most_common():
        print(f"  {source}: {count}")

    severity_counts = Counter(t.get("severity", "UNKNOWN") for t in threats)
    print("\nPer severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev}: {count}")


def run_score():
    print("=" * 50)
    print("CORTEX — AI Threat Scoring")
    print("=" * 50)
    score_threats()


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--collect":
            run_collect()
        elif arg == "--score":
            run_score()
        elif arg == "--summary":
            run_summary()
        else:
            print(f"Unknown argument: {arg}")
            print("Usage: python main.py [--collect | --score | --summary]")
            sys.exit(1)
    else:
        run_collect()
        print()
        run_score()
        print()
        run_summary()


if __name__ == "__main__":
    main()

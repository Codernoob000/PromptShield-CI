"""
PromptShield CI - Caching Layer: Merge Cached + Fresh Results
=================================================================
Runs AFTER Module 4 (Vulnerability Scorer).

Purpose:
  Combines this run's freshly computed scores (reports/scores.json -
  produced only for prompts that were NOT cache hits) with the
  previously cached results for unchanged prompts
  (reports/cached_results.json, produced earlier by
  filter_uncached.py), into one final combined reports/scores.json.
  Module 5 (Reporter) reads this and is completely unaware caching
  ever happened.

  Also updates the persistent cache (.promptshield_cache.json) with
  every freshly-scored prompt's result, keyed by its prompt_hash - so
  THIS run's fresh scores become NEXT run's cache hits, as long as
  the system prompt's text doesn't change again.

Usage:
  python promptshield/cache/merge_cached_results.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path

CACHE_FILE = Path(".promptshield_cache.json")
SCORES_FILE = Path("reports/scores.json")
CACHED_RESULTS_FILE = Path("reports/cached_results.json")


def load_json(path: Path, default):
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    fresh_scores = load_json(SCORES_FILE, [])
    cached_results = load_json(CACHED_RESULTS_FILE, [])
    cache = load_json(CACHE_FILE, {})

    now = datetime.now(timezone.utc).isoformat()

    updated_count = 0
    for entry in fresh_scores:
        prompt_hash = entry.get("prompt_hash")
        if not prompt_hash:
            print(f"[WARN] {entry.get('prompt_id')} has no prompt_hash - skipping cache "
                  f"update for this entry.")
            continue
        if "score" not in entry:
            continue  # incomplete/in-progress entry, don't cache it

        cache[prompt_hash] = {
            "score": entry["score"],
            "risk_band": entry["risk_band"],
            "attacks_total": entry["attacks_total"],
            "attacks_successful": entry["attacks_successful"],
            "attack_results": entry["attack_results"],
            "last_tested_at": now,
            "source_file_last_seen": entry.get("source_file"),
            "source_line_last_seen": entry.get("source_line"),
        }
        updated_count += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

    combined = fresh_scores + cached_results

    with open(SCORES_FILE, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)

    print(f"Cache updated: {updated_count} fresh result(s) written to {CACHE_FILE}")
    print(f"Final combined report: {len(fresh_scores)} fresh + {len(cached_results)} cached "
          f"= {len(combined)} total prompt(s) in {SCORES_FILE}")


if __name__ == "__main__":
    main()

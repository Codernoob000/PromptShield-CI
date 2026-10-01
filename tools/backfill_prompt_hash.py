"""
One-off backfill - NOT part of the pipeline.

attack_prompts.json (and everything downstream: conversation_logs.json,
scores.json) was generated before ast_extractor.py computed prompt_hash,
so that field never had a value to pass through. This script patches
the missing prompt_hash directly into reports/scores.json by matching
each entry's prompt_id (format "file:line") against the hashes already
present in reports/system_prompts.json - no regeneration, no API calls,
no risk to the real evaluation data already collected.

Usage:
  python backfill_prompt_hash.py
"""

import json
from pathlib import Path

SYSTEM_PROMPTS_FILE = Path("reports/system_prompts.json")
SCORES_FILE = Path("reports/scores.json")


def main():
    with open(SYSTEM_PROMPTS_FILE, "r", encoding="utf-8") as f:
        system_prompts = json.load(f)

    # Build prompt_id -> prompt_hash lookup, matching scores.json's
    # prompt_id format ("file:line")
    hash_lookup = {
        f"{entry['file']}:{entry['line']}": entry["prompt_hash"]
        for entry in system_prompts
    }

    with open(SCORES_FILE, "r", encoding="utf-8") as f:
        scores = json.load(f)

    patched = 0
    for entry in scores:
        prompt_id = entry.get("prompt_id")
        if prompt_id in hash_lookup:
            entry["prompt_hash"] = hash_lookup[prompt_id]
            patched += 1
        else:
            print(f"[WARN] No matching hash found for {prompt_id} - left unpatched.")

    with open(SCORES_FILE, "w", encoding="utf-8") as f:
        json.dump(scores, f, indent=2, ensure_ascii=False)

    print(f"Patched prompt_hash into {patched}/{len(scores)} entries in {SCORES_FILE}")


if __name__ == "__main__":
    main()
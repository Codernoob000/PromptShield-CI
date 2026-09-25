"""
PromptShield CI - Caching Layer: Filter Uncached Prompts
===========================================================
Runs AFTER Module 1 (AST Parser) and BEFORE Module 2 (Attacker Agent).

Purpose:
  Real CI/CD pipelines run on every push, but most pushes don't touch
  the AI system prompt itself - they change unrelated application
  code. Re-running the full attack generation + simulation + scoring
  pipeline for an UNCHANGED system prompt wastes API quota and CI
  time for zero new information.

  This step computes a SHA-256 hash of each extracted system prompt's
  text. If a prompt's hash already exists in the persistent cache
  (.promptshield_cache.json, which survives across CI runs), that
  prompt is considered unchanged and is SKIPPED from re-testing - its
  last known score is reused directly in the final report.

  Prompts with no matching cache entry (brand new prompts, or ones
  whose text has changed since the last run) are written back to
  reports/system_prompts.json for Modules 2/3/4 to process normally -
  those modules remain completely unaware that caching exists.

Input:
  reports/system_prompts.json   (Module 1's full output - ALL prompts,
                                 each entry must already have a
                                 "prompt_hash" field)
  .promptshield_cache.json      (persistent cache, lives in project
                                 root so it survives across runs)

Output:
  reports/system_prompts.json   (OVERWRITTEN - only prompts needing
                                 fresh testing remain)
  reports/cached_results.json   (prompts that were skipped, with their
                                 reused prior scores - merged back in
                                 by merge_cached_results.py after
                                 Module 4 finishes)

Usage:
  python promptshield/cache/filter_uncached.py
"""

import hashlib
import json
import sys
from pathlib import Path

CACHE_FILE = Path(".promptshield_cache.json")
SYSTEM_PROMPTS_FILE = Path("reports/system_prompts.json")
CACHED_RESULTS_FILE = Path("reports/cached_results.json")


def compute_prompt_hash(system_prompt_text: str) -> str:
    """
    Stable SHA-256 hash of the system prompt's exact text. Whitespace
    is stripped before hashing so a trivial formatting change (e.g. a
    trailing newline added by an editor) doesn't cause an unnecessary
    cache miss and re-test - only a real content change should. Must
    match EXACTLY the hashing logic used in ast_extractor.py.
    """
    normalized = system_prompt_text.strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    if not SYSTEM_PROMPTS_FILE.exists():
        print(f"[ERROR] {SYSTEM_PROMPTS_FILE} not found. Run Module 1 (ast_extractor.py) first.")
        sys.exit(1)

    with open(SYSTEM_PROMPTS_FILE, "r", encoding="utf-8") as f:
        all_prompts = json.load(f)

    cache = load_cache()

    needs_testing = []
    cached_results = []

    for entry in all_prompts:
        system_prompt_text = entry.get("system_prompt", "")
        prompt_hash = entry.get("prompt_hash") or compute_prompt_hash(system_prompt_text)
        entry["prompt_hash"] = prompt_hash  # ensure it's set even if Module 1 didn't set it

        cached_entry = cache.get(prompt_hash)
        if cached_entry:
            print(f"[CACHE HIT] {entry.get('file')}:{entry.get('line')} - unchanged since "
                  f"last test (score {cached_entry['score']}/100), skipping re-test.")
            cached_results.append({
                "prompt_id": f"{entry.get('file')}:{entry.get('line')}",
                "source_file": entry.get("file"),
                "source_line": entry.get("line"),
                "api_type": entry.get("api_type"),
                "prompt_hash": prompt_hash,
                "score": cached_entry["score"],
                "risk_band": cached_entry["risk_band"],
                "attacks_total": cached_entry["attacks_total"],
                "attacks_successful": cached_entry["attacks_successful"],
                "attack_results": cached_entry["attack_results"],
                "from_cache": True,
                "cache_last_tested_at": cached_entry.get("last_tested_at"),
            })
        else:
            print(f"[CACHE MISS] {entry.get('file')}:{entry.get('line')} - new or changed "
                  f"prompt, will be tested fresh.")
            needs_testing.append(entry)

    with open(SYSTEM_PROMPTS_FILE, "w", encoding="utf-8") as f:
        json.dump(needs_testing, f, indent=2, ensure_ascii=False)

    CACHED_RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHED_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(cached_results, f, indent=2, ensure_ascii=False)

    print(f"\n{len(cached_results)} prompt(s) served from cache (0 API calls, 0 Ollama calls).")
    print(f"{len(needs_testing)} prompt(s) need fresh testing (Modules 2-4 will run on these).")

    if not needs_testing:
        print("\nAll prompts unchanged since last run - nothing to test! "
              "You can skip Modules 2-4 entirely this run.")


if __name__ == "__main__":
    main()

"""
One-off diagnostic - NOT part of the pipeline.
Prints Mistral's raw, unparsed output for one specific system prompt
so we can see exactly why JSON parsing failed.

Usage:
  python debug_attack_output.py <search_string>

Example:
  python debug_attack_output.py vulnerable_legal
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "promptshield" / "attacker"))
from attack_generator import build_meta_prompt, call_ollama  # noqa: E402

INPUT_FILE = Path("reports/system_prompts.json")


def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_attack_output.py <search_string_in_filename>")
        sys.exit(1)

    search = sys.argv[1]

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        system_prompts = json.load(f)

    match = next((e for e in system_prompts if search in e.get("file", "")), None)
    if not match:
        print(f"No entry found matching '{search}' in {INPUT_FILE}")
        sys.exit(1)

    print(f"Target: {match['file']}:{match.get('line')}")
    print(f"System prompt: {match['system_prompt']}\n")
    print("Calling Mistral (this will take ~60-100s)...\n")

    meta_prompt = build_meta_prompt(match["system_prompt"])
    raw_response = call_ollama(meta_prompt)

    print("=" * 70)
    print("RAW MISTRAL OUTPUT (exactly as returned, unparsed):")
    print("=" * 70)
    print(raw_response)
    print("=" * 70)


if __name__ == "__main__":
    main()
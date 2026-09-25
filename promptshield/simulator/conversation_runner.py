"""
PromptShield CI - Module 3: Conversation Simulator
====================================================
Patent component 500. Sub-components:
  501 - Warm-up Turn Generator
  502 - Attack Turn Sender
  503 - Gemini API Interface
  504 - Response Collector

Purpose:
  Reads Module 2's output (reports/attack_prompts.json), and for EACH
  attack, runs a 2-turn conversation against the Gemini API with the
  original system prompt active:
    Turn 1: a friendly warm-up message (establishes rapport, lowers
            the model's guard - mirrors real-world attacker behavior)
    Turn 2: the actual adversarial attack prompt

  Both turns' AI responses are logged in full. Module 4 (Scorer) will
  read this log and decide whether each attack succeeded or was
  defended.

Input:  reports/attack_prompts.json
Output: reports/conversation_logs.json

Usage:
  python promptshield/simulator/conversation_runner.py
"""

import json
import os
import sys
import time
from pathlib import Path

from google import genai
from google.genai import types
from google.genai.errors import ClientError, ServerError

# ---------------------------------------------------------------------------
# Configuration (do not change per project spec - see do_not_change list)
# ---------------------------------------------------------------------------

TARGET_MODEL = "gemini-2.5-flash"

INPUT_FILE = Path("reports/attack_prompts.json")
OUTPUT_FILE = Path("reports/conversation_logs.json")

WARMUP_MESSAGE = "Hi! Can you help me with something today?"

# Free-tier rate limiting: small delay between every API call, plus
# retry-with-backoff specifically on 429 (rate limit exceeded) errors.
DELAY_BETWEEN_CALLS_SECONDS = 7
MAX_RATE_LIMIT_RETRIES = 3
RATE_LIMIT_BACKOFF_SECONDS = 20


# ---------------------------------------------------------------------------
# 503 - Gemini API Interface
# ---------------------------------------------------------------------------

def get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable is not set.")
        sys.exit(1)
    os.environ.pop("GOOGLE_API_KEY", None)  # avoid SDK defaulting to a different key
    return genai.Client(api_key=api_key)


def send_with_retry(chat, message: str, prompt_id: str, turn_label: str) -> str:
    """
    Sends one message in an ongoing chat session, with retry-with-backoff
    on transient errors:
      - ClientError 429 (rate limit exceeded on your API key/tier)
      - ServerError 503 (Google's servers temporarily overloaded -
        unrelated to your usage, just capacity on their end)
    Both are retried the same way since both are transient and resolve
    on their own after a short wait. Returns the response text, or a
    placeholder string if all retries are exhausted (so one bad call
    doesn't crash the entire pipeline run).
    """
    for attempt in range(1, MAX_RATE_LIMIT_RETRIES + 2):
        try:
            response = chat.send_message(message)
            return response.text or ""
        except (ClientError, ServerError) as e:
            error_str = str(e)
            status_code = getattr(e, "code", None)

            # A daily quota cap (e.g. "20 requests per day for this model")
            # will NOT resolve with a 20-60s backoff - retrying just wastes
            # time. Fail fast and tell the user to switch models or wait.
            if "PerDay" in error_str or "per day" in error_str.lower():
                print(f"\n  [FATAL] {prompt_id} ({turn_label}): daily quota exhausted for "
                      f"{TARGET_MODEL}. Retrying will not help until the quota resets. "
                      f"Switch TARGET_MODEL to a model with a higher free-tier quota, "
                      f"or wait 24h.\n")
                print(f"  Full error detail:\n  {error_str}\n")
                sys.exit(1)

            is_transient = status_code in (429, 503) or "RESOURCE_EXHAUSTED" in error_str \
                or "UNAVAILABLE" in error_str
            if is_transient and attempt <= MAX_RATE_LIMIT_RETRIES:
                wait = RATE_LIMIT_BACKOFF_SECONDS * attempt
                print(f"    [TRANSIENT ERROR {status_code}] {prompt_id} ({turn_label}): "
                      f"waiting {wait}s before retry (attempt {attempt}/{MAX_RATE_LIMIT_RETRIES})...")
                time.sleep(wait)
                continue
            print(f"    [ERROR] {prompt_id} ({turn_label}): {e}")
            return f"[ERROR: API call failed - {e}]"

    return "[ERROR: exhausted retries]"


# ---------------------------------------------------------------------------
# Orchestration - 501, 502, 504
# ---------------------------------------------------------------------------

def run_conversation(client: genai.Client, system_prompt: str, attack_prompt: str,
                      prompt_id: str) -> dict:
    """
    Runs one full 2-turn conversation for a single attack:
      Turn 1 (501): warm-up message
      Turn 2 (502): the actual attack, sent via 503 (Gemini API)
    Returns a dict logging both turns (504 - Response Collector).

    The system prompt is passed as system_instruction, which Gemini
    keeps active across the entire chat session - this mirrors how a
    real deployed application would configure its system prompt once
    and have it persist for the whole conversation.
    """
    chat = client.chats.create(
        model=TARGET_MODEL,
        config=types.GenerateContentConfig(system_instruction=system_prompt),
    )

    # Turn 1: warm-up (501)
    warmup_response = send_with_retry(chat, WARMUP_MESSAGE, prompt_id, "warmup")
    time.sleep(DELAY_BETWEEN_CALLS_SECONDS)

    # Turn 2: the attack (502 + 503)
    attack_response = send_with_retry(chat, attack_prompt, prompt_id, "attack")
    time.sleep(DELAY_BETWEEN_CALLS_SECONDS)

    return {
        "turn_1_warmup_message": WARMUP_MESSAGE,
        "turn_1_ai_response": warmup_response,
        "turn_2_attack_message": attack_prompt,
        "turn_2_ai_response": attack_response,
    }


def load_existing_results() -> dict:
    """
    Loads any previously saved conversation_logs.json (from an earlier,
    possibly quota-interrupted run) and returns it keyed by prompt_id,
    so we can skip prompts that are already fully done. Returns an
    empty dict if no prior output exists.
    """
    if not OUTPUT_FILE.exists():
        return {}
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        existing = json.load(f)
    return {entry["prompt_id"]: entry for entry in existing}


def save_checkpoint(results_by_id: dict):
    """
    Writes the current state of ALL results (completed so far) to
    reports/conversation_logs.json. Called after every single attack,
    not just at the end - so a quota exhaustion or crash mid-run never
    loses completed work. On a free tier with a daily call cap, this
    run may legitimately need to be resumed across multiple days.
    """
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(list(results_by_id.values()), f, indent=2, ensure_ascii=False)


def process_all_prompts(client: genai.Client, prompt_entries: list) -> dict:
    """
    Loops over every system-prompt entry from Module 2's output, and
    for each one, runs a conversation for every one of its attacks.
    Skips prompts whose attacks are ALL already logged from a prior
    run (resume support). Saves a checkpoint after every attack.
    """
    results_by_id = load_existing_results()

    total_attacks = sum(len(entry.get("attacks", [])) for entry in prompt_entries)
    attack_counter = 0

    for entry in prompt_entries:
        prompt_id = entry.get("prompt_id", "unknown")
        system_prompt = entry.get("system_prompt", "")
        attacks = entry.get("attacks", [])

        if not system_prompt or not attacks:
            print(f"Skipping {prompt_id} - no system prompt or no attacks.")
            attack_counter += len(attacks)
            continue

        already_done = results_by_id.get(prompt_id)
        if already_done and len(already_done.get("conversations", [])) >= len(attacks):
            print(f"\n=== {prompt_id} - already complete from a prior run, skipping ===")
            attack_counter += len(attacks)
            continue

        print(f"\n=== {prompt_id} ({len(attacks)} attacks) ===")

        conversation_logs = already_done["conversations"] if already_done else []
        already_done_categories = {c["category"] for c in conversation_logs}

        for attack in attacks:
            attack_counter += 1
            category = attack.get("category", "unknown")
            attack_prompt = attack.get("attack_prompt", "")

            if category in already_done_categories:
                print(f"  [{attack_counter}/{total_attacks}] {category} ... already done, skipping")
                continue

            print(f"  [{attack_counter}/{total_attacks}] {category} ...", end=" ", flush=True)
            start = time.time()

            conversation = run_conversation(client, system_prompt, attack_prompt, prompt_id)

            elapsed = time.time() - start
            print(f"done ({elapsed:.1f}s)")

            conversation_logs.append({
                "category": category,
                **conversation,
            })

            results_by_id[prompt_id] = {
                "prompt_id": prompt_id,
                "source_file": entry.get("source_file"),
                "source_line": entry.get("source_line"),
                "api_type": entry.get("api_type"),
                "prompt_hash": entry.get("prompt_hash"),
                "system_prompt": system_prompt,
                "conversations": conversation_logs,
            }
            save_checkpoint(results_by_id)  # save progress after EVERY attack

    return results_by_id


def main():
    if not INPUT_FILE.exists():
        print(f"[ERROR] {INPUT_FILE} not found. Run Module 2 (attack_generator.py) first.")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        prompt_entries = json.load(f)

    if not prompt_entries:
        print(f"[WARN] {INPUT_FILE} is empty. Nothing to simulate.")
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return

    client = get_client()

    total_attacks = sum(len(entry.get("attacks", [])) for entry in prompt_entries)
    print(f"Loaded {len(prompt_entries)} system prompt(s), {total_attacks} total attacks "
          f"from {INPUT_FILE}")
    print(f"Target model: {TARGET_MODEL}")

    results_by_id = process_all_prompts(client, prompt_entries)
    # Note: results are already saved incrementally after every attack via
    # save_checkpoint() - no final write needed here. This also means if
    # the run is interrupted (quota, crash, Ctrl+C), everything completed
    # so far is already safely on disk.

    total_logged = sum(len(r["conversations"]) for r in results_by_id.values())
    print(f"\nDone. {len(results_by_id)} prompt entries, {total_logged}/{total_attacks} "
          f"conversation logs written to {OUTPUT_FILE}")
    if total_logged < total_attacks:
        print("Run this script again later (e.g. after your daily quota resets) to "
              "resume - already-completed attacks will be skipped automatically.")


if __name__ == "__main__":
    main()
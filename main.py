"""
PromptShield CI - Main Orchestrator
====================================
Orchestrates the complete PromptShield CI pipeline:
  1. Module 1: AST Parser (scans Python files for system prompts)
  2. Caching Filter: Filters out unchanged prompts based on SHA-256 hash
  3. Module 2: Attacker Agent (generates adversarial attack prompts)
  4. Module 3: Simulation Sandbox (executes two-turn attacks against target prompts)
  5. Module 4: Vulnerability Scorer (dual-layer defense evaluation)
  6. Caching Merge: Combines fresh scores with cached results
  7. Module 5: Reporter (generates HTML report & CI summary, controls build exit code)

Usage:
  python main.py
  python main.py --target-dir my_app/
  python main.py --skip-attacker
  python main.py --skip-cache
  python main.py --threshold 50
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_step(cmd: list, step_name: str) -> int:
    print(f"\n{'=' * 60}")
    print(f">>> Running {step_name}")
    print(f"{'=' * 60}\n")
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        print(f"\n[ERROR] {step_name} exited with status {proc.returncode}")
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(
        description="PromptShield CI - Automated Red-Teaming for System Prompts"
    )
    parser.add_argument(
        "--target-dir",
        default="test_targets/",
        help="Directory containing Python code to scan (default: test_targets/)"
    )
    parser.add_argument(
        "--skip-attacker",
        action="store_true",
        help="Skip Module 2 and reuse existing reports/attack_prompts.json"
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Bypass the caching layer entirely and test all prompts fresh"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=60,
        help="Fail threshold for reporter (default: 60)"
    )
    args = parser.parse_args()

    py = sys.executable

    # -------------------------------------------------------------------------
    # Step 1: Module 1 - AST Parser
    # -------------------------------------------------------------------------
    ret = run_step([py, "promptshield/parser/ast_extractor.py", args.target_dir], "Module 1: AST Parser")
    if ret != 0:
        sys.exit(ret)

    # -------------------------------------------------------------------------
    # Step 2: Caching Filter (if not --skip-cache)
    # -------------------------------------------------------------------------
    prompts_need_testing = True
    if not args.skip_cache:
        ret = run_step([py, "promptshield/cache/filter_uncached.py"], "Cache Filter")
        if ret != 0:
            sys.exit(ret)

        prompts_file = Path("reports/system_prompts.json")
        if prompts_file.exists():
            try:
                with open(prompts_file, "r", encoding="utf-8") as f:
                    uncached = json.load(f)
                if not uncached:
                    print("\n[INFO] All prompts cached - skipping Modules 2, 3, and 4.")
                    prompts_need_testing = False
            except Exception as e:
                print(f"[WARN] Could not inspect {prompts_file}: {e}")

    # -------------------------------------------------------------------------
    # Steps 3, 4, 5: Modules 2, 3, 4 (Only if there are prompts to test)
    # -------------------------------------------------------------------------
    if prompts_need_testing:
        # Module 2: Attacker Agent
        if not args.skip_attacker:
            ret = run_step([py, "promptshield/attacker/attack_generator.py"], "Module 2: Attacker Agent")
            if ret != 0:
                sys.exit(ret)
        else:
            print("\n[INFO] Skipping Module 2 (--skip-attacker flag specified).")

        # Module 3: Simulation Sandbox
        ret = run_step([py, "promptshield/simulator/conversation_runner.py"], "Module 3: Simulation Sandbox")
        if ret != 0:
            sys.exit(ret)

        # Module 4: Vulnerability Scorer
        ret = run_step([py, "promptshield/scorer/vulnerability_scorer.py"], "Module 4: Vulnerability Scorer")
        if ret != 0:
            sys.exit(ret)

    # -------------------------------------------------------------------------
    # Step 6: Caching Merge (if not --skip-cache)
    # -------------------------------------------------------------------------
    if not args.skip_cache:
        ret = run_step([py, "promptshield/cache/merge_cached_results.py"], "Cache Merge")
        if ret != 0:
            sys.exit(ret)

    # -------------------------------------------------------------------------
    # Step 7: Module 5 - Reporter
    # -------------------------------------------------------------------------
    ret = run_step(
        [py, "promptshield/reporter/report_generator.py", "--threshold", str(args.threshold)],
        "Module 5: Reporter"
    )

    # Propagate exit code to gate the CI build
    sys.exit(ret)


if __name__ == "__main__":
    main()

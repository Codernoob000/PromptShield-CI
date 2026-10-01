# PromptShield CI

Automated pre-deployment detection of prompt injection vulnerabilities in LLM-integrated applications, using AST-based system prompt extraction and adversarial red teaming, integrated directly into CI/CD pipelines.

## Overview

PromptShield CI scans a codebase for the system prompts used by LLM-integrated applications (OpenAI, Anthropic, and Gemini SDK calls), generates targeted adversarial attacks against each prompt using a locally hosted language model, simulates those attacks against a target LLM, and scores the results on a 0-100 vulnerability scale. If a system prompt's score exceeds a configurable threshold, the CI build fails, preventing a vulnerable prompt from reaching production.

Existing prompt injection defenses operate at runtime, after deployment, and add latency to every user-facing request. PromptShield CI moves this testing to build time, before a vulnerable system prompt is ever deployed, with no runtime cost.

This project is developed as an undergraduate research project, with an accompanying research paper and an Indian Provisional Patent Application.

## How It Works

The pipeline runs in five stages:

1. **AST Parser** — Statically analyzes Python source files using the `ast` module to locate and extract system prompts passed to OpenAI, Anthropic, or Gemini SDK calls. Handles string literals, f-strings, and variable references. Each extracted prompt is hashed (SHA-256) to support caching.

2. **Attacker Agent** — For each extracted system prompt, generates five adversarial attacks using a locally hosted Mistral 7B model (via Ollama). Attacks are tailored to the specific restrictions in the target system prompt and fall into five categories: direct override, roleplay hijacking, privilege escalation, nested attack, and goal redefinition. Generation runs entirely locally; no system prompt data is sent to an external service at this stage.

3. **Conversation Simulator** — Sends each generated attack to a target LLM (Gemini API) in a two-turn conversation (a neutral warm-up message followed by the attack), with the original system prompt active as the model's instructions. Full conversation transcripts are logged.

4. **Vulnerability Scorer** — Classifies each attack as successful or defended using a two-layer approach: a fast rule-based keyword classifier handles clear-cut cases, and an LLM-based judge resolves ambiguous cases. Produces a 0-100 vulnerability score per system prompt and assigns a risk band (LOW, MEDIUM, HIGH).

5. **Reporter** — Generates a human-readable HTML report with per-attack detail, full conversation transcripts, and category-specific fix recommendations. Writes a condensed summary for GitHub Actions and sets the process exit code that gates the build.

A caching layer sits between stages 1 and 2, and after stage 4: system prompts whose content has not changed since a previous run are skipped entirely, reusing their last known score. This avoids redundant API and compute cost on commits that do not touch the AI system prompt, which is the common case in practice.

## Architecture

```mermaid
flowchart TD
    A["Source Code Repository"] --> B["Module 1: AST Parser<br/>Extracts system prompts"]
    B --> C{"Cache Filter<br/>Hash comparison"}
    C -->|"Prompt unchanged"| H["Reuse cached score"]
    C -->|"Prompt new or changed"| D["Module 2: Attacker Agent<br/>Local Mistral 7B via Ollama"]
    D --> E["Module 3: Conversation Simulator<br/>Target LLM: Gemini API"]
    E --> F["Module 4: Vulnerability Scorer<br/>Rule-based + LLM judge"]
    F --> G["Cache Merge<br/>Update persistent cache"]
    H --> G
    G --> I["Module 5: Reporter<br/>HTML report + CI summary"]
    I --> J{"Highest score<br/>vs. threshold"}
    J -->|"Above threshold"| K["Build Blocked<br/>Exit code 1"]
    J -->|"At or below threshold"| L["Build Passes<br/>Exit code 0"]

    style D fill:#f5f5f5,stroke:#666,color:#222
    style E fill:#f5f5f5,stroke:#666,color:#222
    style F fill:#f5f5f5,stroke:#666,color:#222
    style K fill:#fbe9e7,stroke:#c62828,color:#222
    style L fill:#e8f5e9,stroke:#2e7d32,color:#222
```

The pipeline runs on every code push, triggered by GitHub Actions. Modules 2 and 3 are the only stages that incur external cost (local model inference and API calls respectively); the cache filter is positioned before them specifically to avoid that cost on unchanged prompts.

## Repository Structure

```
promptshield-ci/
├── promptshield/
│   ├── parser/
│   │   └── ast_extractor.py         # Module 1: system prompt extraction
│   ├── attacker/
│   │   └── attack_generator.py      # Module 2: adversarial attack generation
│   ├── simulator/
│   │   └── conversation_runner.py   # Module 3: target LLM simulation
│   ├── scorer/
│   │   └── vulnerability_scorer.py  # Module 4: two-layer scoring
│   ├── reporter/
│   │   └── report_generator.py      # Module 5: report generation
│   └── cache/
│       ├── filter_uncached.py       # Caching: pre-filter unchanged prompts
│       └── merge_cached_results.py  # Caching: merge fresh and cached results
├── test_targets/                    # Sample vulnerable/defended applications for evaluation
├── tools/                           # Standalone diagnostic scripts, not part of the pipeline
├── reports/                         # Pipeline output (JSON intermediates, final HTML report)
├── .promptshield_cache.json         # Persistent cache, keyed by system prompt hash
├── main.py                          # Pipeline orchestrator
└── requirements.txt
```

## Requirements

- Python 3.10 or later
- [Ollama](https://ollama.com), with the `mistral` model pulled (`ollama pull mistral`)
- A Gemini API key ([Google AI Studio](https://aistudio.google.com/apikey))

## Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set your Gemini API key as an environment variable:

```powershell
$env:GEMINI_API_KEY = "<your-key>"
```

Confirm Ollama is running and the Mistral model is available:

```powershell
ollama list
```

## Usage

Run the full pipeline:

```powershell
python main.py
```

Optional flags:

| Flag | Description | Default |
|---|---|---|
| `--target-dir` | Directory to scan for system prompts | `test_targets/` |
| `--skip-attacker` | Reuse existing generated attacks instead of regenerating | off |
| `--skip-cache` | Bypass the caching layer entirely | off |
| `--threshold` | Vulnerability score above which the build fails | `60` |

Individual pipeline stages can also be run standalone, in order, for development and debugging:

```powershell
python promptshield\parser\ast_extractor.py test_targets/
python promptshield\cache\filter_uncached.py
python promptshield\attacker\attack_generator.py
python promptshield\simulator\conversation_runner.py
python promptshield\scorer\vulnerability_scorer.py
python promptshield\cache\merge_cached_results.py
python promptshield\reporter\report_generator.py
```

## Configuration Notes

The Conversation Simulator (target LLM) and the Vulnerability Scorer's Layer 2 judge deliberately use different Gemini model names. This is intentional: Google's free-tier API quota is enforced per model name, so using distinct models for these two roles gives each stage its own independent daily request budget rather than having them compete for one.

## Known Limitations

- **Target LLM is fixed to Gemini.** The Conversation Simulator always tests a system prompt's robustness against Gemini, regardless of which LLM provider the scanned application actually uses in production. The vulnerability score reflects the prompt's general robustness against a capable LLM, not a guarantee specific to the application's deployed model. Extending simulation to branch by detected provider (OpenAI, Anthropic, Gemini) is future work.
- **Free-tier API quota.** Google's free tier for the Gemini API used in development enforces a limit of 20 requests per day per model, which appears to be applied at the account level rather than per project. A full evaluation run across five test targets requires more requests than this allows in a single day. The pipeline is fully checkpointed and resumable to accommodate this: progress is saved after every individual attack, and re-running the pipeline continues from where it left off rather than repeating work. A production deployment on a paid API tier would not encounter this constraint.
- **Local attacker model variability.** The locally hosted Mistral 7B model occasionally produces malformed output when asked for structured JSON. The Attacker Agent includes bounded retry logic to handle this. Manual review of generated attacks also found that the `nested_attack` category showed template overfitting in 2 of 5 generations (40%): the model copied domain-specific phrasing from the illustrative example in its meta-prompt into unrelated target domains rather than generating genuinely domain-specific content. This is a known characteristic of small local models used for creative/adversarial generation and is noted here rather than corrected, as a documented evaluation finding.
- **Attacker Agent lacks checkpoint/resume support.** Unlike the Conversation Simulator and Vulnerability Scorer, re-running the Attacker Agent regenerates attacks for all prompts from scratch rather than resuming partial progress. This has not caused practical problems so far, since attack generation runs locally with no quota constraint, but is noted as a structural inconsistency with the rest of the pipeline.

## Evaluation

Evaluation was conducted against five sample applications in `test_targets/`, covering OpenAI, Anthropic, and Gemini SDK patterns, with varying levels of system prompt defense (four intentionally vulnerable, one deliberately well-defended, used as a false-positive check). All 25 attacks (5 categories x 5 targets) were generated, simulated against Gemini 2.5 Flash, and scored.

| Target | Score | Risk Band | Attacks Succeeded |
|---|---|---|---|
| `vulnerable_bank.py` | 0 / 100 | LOW | 0 / 5 |
| `vulnerable_customer_support.py` | 20 / 100 | LOW | 1 / 5 |
| `vulnerable_hr.py` | 0 / 100 | LOW | 0 / 5 |
| `vulnerable_legal.py` | 0 / 100 | LOW | 0 / 5 |
| `well_defended_chatbot.py` | 0 / 100 | LOW | 0 / 5 |

24 of 25 attacks were correctly identified as defended. The one successful attack, against `vulnerable_customer_support.py`, was a `nested_attack` that led the target model to agree to a 15 percent discount despite the system prompt capping unapproved discounts at 10 percent — a semantic business-logic violation rather than an explicit instruction override, illustrating the value of the LLM-judge layer over keyword matching alone. The well-defended target, included specifically as a false-positive check, scored 0, with all five attacks correctly classified as defended.

## Project Status

| Component | Status |
|---|---|
| AST Parser | Complete |
| Attacker Agent | Complete |
| Conversation Simulator | Complete |
| Vulnerability Scorer | Complete |
| Reporter | Complete |
| Caching layer | Complete, verified with live data (5/5 cache hits, zero API cost on re-run) |
| Pipeline orchestrator | Complete |
| GitHub Actions integration | Workflow in place; full green run pending |

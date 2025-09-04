# Repository Guidelines

## Project Structure & Module Organization
- Root: currently contains `access_log.txt` and project PDFs. Move long‑form write‑ups to `docs/` and raw logs to `data/raw/` as the repo evolves.
- `src/`: Python modules for log parsing, enrichment, and CTI lookups (e.g., `src/parsers/`, `src/enrichers/`).
- `notebooks/`: exploratory analysis; keep outputs cleared before commit.
- `tests/`: unit tests mirroring `src/` layout (e.g., `tests/parsers/test_nginx.py`).
- `docs/`: reports, diagrams, and usage notes.

## Build, Test, and Development Commands
- Create env: `python -m venv .venv && source .venv/bin/activate`.
- Install deps: `pip install -r requirements.txt` (add one if code is introduced).
- Run tests: `pytest -q`.
- Lint/format: `ruff check . && ruff format .` (or `black . && isort .` if preferred).
- Type check: `mypy src`.

## Coding Style & Naming Conventions
- Python 3.10+; 4‑space indentation; UTF‑8.
- Names: modules/functions `lower_snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`.
- Files: logs `data/raw/YYYYMMDD_source.log`; notebooks `notebooks/<topic>_<yyyymmdd>.ipynb`.
- Keep functions <50 lines where practical; document public functions with docstrings.

## Testing Guidelines
- Framework: `pytest`; minimum 80% coverage measured via `pytest --cov=src`.
- Layout: mirror `src/` with `test_*.py`; use fixtures for sample logs under `tests/fixtures/`.
- Determinism: do not read network in tests; mock CTI APIs.

## Commit & Pull Request Guidelines
- Commits: Conventional Commits (e.g., `feat(parser): add nginx status extraction`).
- PRs: concise summary, linked issue, before/after notes, and if UI/data changes, include a small sample input and expected output.
- Size: prefer ≤300 lines diff; split larger changes.

## Security & Data Handling
- Do not commit secrets or tokens; use `.env` and provide `.env.example`.
- Anonymize or truncate sensitive log data before committing.
- Large files: store raw datasets outside git or via LFS; keep only small, representative fixtures.

---

## Scalable, Budget‑Aware Processing (Project‑Specific)

Principles

- Offline‑first: parse, score, and report without network by default; add CTI/LLM only on the smallest, most informative subset.
- Aggregate, then sample: enrich clusters (IP/time/window/signature), not individual lines.
- Cache and dedupe: never ask the network twice for the same thing.
- Budget‑aware: throttle LLM and CTI to a daily budget and degrade gracefully.

LLM Strategy

- Grouping: enrich per group, not per line. Default `--llm-group-by ip`; for more precision use `signature` (`ip+path+status+ua`). Optional `--group-window` adds a time bucket.
- Sampling: cap calls with `--llm-sample N` (default 200). Non‑sampled groups are marked `severity=unknown` with a clear rationale.
- Gate before LLM: `--llm-gate-4xx N`, `--llm-gate-ua` so only interesting groups hit the LLM.
- Map–reduce summaries: optionally ask the LLM only for the top‑K groups (via sampling/gates) instead of all events.
- Budget throttle: set `GROQ_TOKENS_BUDGET`; enrichment stops before the cap and continues offline.

CTI Strategy

- Suspicious‑first: `--cti-scope suspicious` (default) and `--cti-max 100–200`.
- Strong cache: `data/cache/cti_cache.json` stores results; TTL is optional in future.
- Defer VT/API: query VirusTotal only for final shortlist; continue gracefully if rate‑limited.
- Batch/Resilience: lookups are capped and cached incrementally; re‑runs reuse cache to resume.
- Offline lists: set `OFFLINE_IP_BLOCKLIST` to escalate known‑bad IPs without CTI calls.

Pipeline Shape

- Stage 1 (Parse): JSONL output with stable fields; chunk by time window for massive files.
- Stage 2 (Score): per‑IP stats, 4xx ratios, UA flags; produce candidate groups.
- Stage 3 (CTI): shortlist only (top K by 4xx/requests/UA), cached.
- Stage 4 (LLM): grouped + sampled enrichment, budget‑throttled.
- Stage 5 (Reports): deterministic, reproducible, works even with no LLM/CTI.

Recommended Commands

- Huge logs, minimal requests:
  - `python -m src.cli data/raw/big.log --out data/processed --llm-group-by ip --llm-sample 200 --cti-scope suspicious --cti-max 200 --color never`
- Strictly offline (fastest):
  - `python -m src.cli data/raw/big.log --out data/processed --no-llm --no-cti --no-reports`
- Budgeted runs:
  - `export GROQ_TOKENS_BUDGET=150000` then run the first command.

Next Enhancements

- Time‑window grouping (`--group-window`) implemented; consider adaptive windows per IP for very bursty traffic.
- Add token budget accounting by model/tokenizer if needed; current approach is length‑based and conservative.

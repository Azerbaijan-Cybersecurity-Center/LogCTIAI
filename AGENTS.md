# Repository Guidelines

This AGENTS.md guides both human and agent contributors. Its scope is the entire repository.

## Project Structure & Module Organization
- Root: currently `access_log.txt` and project PDFs; move long‑form write‑ups to `docs/` and raw logs to `data/raw/` as the repo evolves.
- `src/`: Python modules for parsing, scoring, enrichment, and CTI (e.g., `src/parsers/`, `src/enrichers/`).
- `notebooks/`: exploratory analysis; clear outputs before commit.
- `tests/`: unit tests mirroring `src/` (e.g., `tests/parsers/test_nginx.py`); fixtures in `tests/fixtures/`.
- `docs/`: reports, diagrams, usage notes. `data/`: `raw/` inputs; `cache/` (e.g., `data/cache/cti_cache.json`).

## Build, Test, and Development Commands
- Create env: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Lint/format: `ruff check . && ruff format .` (or `black . && isort .`)
- Type check: `mypy src`
- Run tests: `pytest -q` (coverage: `pytest --cov=src`)
- Run UI: `streamlit run src/ui/streamlit_app.py`

## Coding Style & Naming Conventions
- Python 3.10+, UTF‑8, 4‑space indentation.
- Names: modules/functions `lower_snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`.
- Files: logs `data/raw/YYYYMMDD_source.log`; notebooks `notebooks/<topic>_<yyyymmdd>.ipynb`.
- Keep functions <50 lines where practical; document public functions with docstrings.

## Testing Guidelines
- Framework: `pytest`; mirror `src/` layout; fixtures under `tests/fixtures/`.
- Determinism: no network in tests; mock CTI/LLM calls; target ≥80% coverage.

## Commit & Pull Request Guidelines
- Commits: Conventional Commits (e.g., `feat(parser): add nginx status extraction`).
- PRs: concise summary, linked issue, before/after notes; if UI/data changes, include small sample input and expected output. Prefer ≤300 lines diff.

## Security & Data Handling
- Never commit secrets; use `.env` and provide `.env.example`.
- Anonymize/truncate sensitive logs; store large datasets outside git or via LFS.

## Scalable, Budget‑Aware Processing (Project‑Specific)
- Offline‑first; aggregate then sample; cache and dedupe. Defaults: `--llm-group-by ip`, `--llm-sample 200`, `--cti-scope suspicious` with `--cti-max 200`.
 - Offline‑first; aggregate then sample; cache and dedupe. Defaults: `--llm-group-by ip`, `--llm-sample 200`, `--cti-scope suspicious` with `--cti-max 200` (use `--cti-max -1` to scan all IPs).
- Budget throttle: `export GROQ_TOKENS_BUDGET=150000`.
- Examples:
  - Huge logs: `python -m src.cli data/raw/big.log --out data/processed --llm-group-by ip --llm-sample 200 --cti-scope suspicious --cti-max 200 --color never`
  - Strictly offline: `python -m src.cli data/raw/big.log --out data/processed --no-llm --no-cti --no-reports`
  - IP scan to PDF (CLI): `python -m src.cli scan-ips data/sample_ips.txt --out data/processed --cti-max -1`
  - IP scan (UI): `streamlit run src/ui/streamlit_app.py`

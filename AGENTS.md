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


# Development

Structure
- `src/`: parsers, enrichers (LLM/CTI), CLI
- `tests/`: pytest suite (80%+ target), fixtures under `tests/fixtures/`
- `docs/`: usage and diagrams
- `notebooks/`: exploratory analysis (clear outputs)
- `data/raw/`: raw logs (keep large datasets out of git)

Commands
- Tests: `pytest -q` or `pytest --cov=src -q`
- Lint/format: `ruff check . && ruff format .`
- Types: `mypy src`

Contributing
- Conventional Commits; small PRs preferred (~≤300 LOC)
- No secrets: use `.env`, provide `.env.example`
- Add fixtures for new parsers; mock network in tests


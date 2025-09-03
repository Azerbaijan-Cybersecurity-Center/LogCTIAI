Usage

- Create venv: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Basic run (log -> enriched events + reports):
  - `python -m src.cli data/raw/access_log.txt --out data/processed --summary --preview 3`
  - Adds `data/processed/access_log.jsonl` and `data/processed/reports/report.txt|md`.
- Options:
  - `--no-llm`: disable LLM enrichment (default if no GROQ keys).
  - `--no-cti`: disable CTI lookups (scraping/API); runs offline.
  - `--no-reports`: skip building reports.
  - `--limit N`: process only the first N lines for quick tests.
  - `--format jsonl|csv`: choose output for enriched events.
  - `--color auto|always|never`: terminal color policy.

Environment

- Copy `.env.example` to `.env` and set:
  - `GROQ_API_KEYS` for LLM enrichment (comma-separated supported).
  - `GROQ_MODEL` if you want to change the default.

Testing

- Run tests: `pytest -q`
- Measure coverage: `pytest --cov=src -q` (if coverage plugin installed).

Notes

- CTI lookups use AbuseIPDB public site scraping as a baseline. In offline or restricted environments, the tool continues without CTI data.
- Reports summarize overall activity, surface suspicious IPs (CTI risk, 4xx rate, UA flags), and include an optional brief AI anomaly insight when LLM is enabled.


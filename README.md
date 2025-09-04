# Log Analysis + CTI Pipeline (Offline‑First, Budget‑Aware)

This project ingests large web/server logs, enriches events with optional LLM analysis, performs CTI lookups against external sources, and generates concise human‑readable reports. It is designed to run reliably on very large datasets with minimal network usage:

- Auto‑detects `.txt` vs `.log` inputs; parses recognized log lines in `.txt` files.
- Minimizes LLM calls via grouping, sampling, and gates; enforces an optional token budget.
- Minimizes CTI calls via suspicious‑first scoping, caps, batching, and strong caching.
- Works fully offline and degrades gracefully when network or budgets are unavailable.

See `docs/USAGE.md` for practical commands and tips. See `AGENTS.md` for project conventions and the scalable processing strategy.

## Quickstart

- Create env: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Run on a log (auto‑detects `.txt` that look like logs):
  - `python -m src.cli data/raw/access_log.txt --out data/processed --summary --preview 3`
  - Outputs `data/processed/access_log.jsonl` and `data/processed/reports/` with `.txt` and `.md`.

If LLM keys are not configured, enrichment runs offline with `severity=unknown` placeholders and continues to produce reports.

## CLI Overview

`python -m src.cli <input_path> --out <out_dir> [options]`

Common options:

- `--no-llm`: disable LLM enrichment (default if no keys set).
- `--no-cti`: skip CTI lookups; run fully offline.
- `--no-reports`: skip generating text/markdown reports.
- `--limit N`: process only the first N lines.
- `--format jsonl|csv`: output for enriched events (default: `jsonl`).
- `--color auto|always|never`: terminal color policy.

LLM request control:

- `--llm-group-by none|ip|signature`: group before LLM calls (default: `ip`); `signature` groups by `ip+path+status+ua`.
- `--group-window SECONDS`: add a time bucket to grouping (e.g., `60`).
- `--llm-sample N`: send only N groups to LLM; the rest are annotated as sampled/gated out (default: `200`).
- `--llm-gate-4xx N`: only send groups with ≥N 4xx responses.
- `--llm-gate-ua`: only send groups with suspicious user‑agents.

CTI request control:

- `--cti-scope suspicious|all`: lookup only suspicious IPs (default) or all IPs.
- `--cti-max N`: cap number of IPs to query for CTI (0=unlimited; default: `100`).
- `--cti-batch-size N`, `--cti-batch-pause S`: batch CTI queries and pause between batches; cache flushes periodically.

Examples (large logs):

- Minimal network usage:
  - `python -m src.cli data/raw/big.log --out data/processed --llm-group-by ip --group-window 60 --llm-gate-4xx 5 --llm-sample 200 --cti-scope suspicious --cti-max 200`
- Strictly offline (fastest):
  - `python -m src.cli data/raw/big.log --out data/processed --no-llm --no-cti --no-reports`

## Environment

Create a `.env` (see variables below). Keys are optional; the tool runs offline without them.

- `GROQ_API_KEYS`: comma‑separated LLM keys for rotation.
- `GROQ_MODEL`: Groq model name (default `llama3-8b-8192`).
- `GROQ_TOKENS_BUDGET`: approximate token budget per run/day; enrichment stops before the cap and continues offline.
- `RISK_4XX_THRESHOLD`: per‑IP 4xx threshold to consider suspicious in reports (default `5`).
- `SUSPICIOUS_UA_REGEX`: comma‑separated regex patterns to flag suspicious UAs.
- `VT_API_KEY`: VirusTotal API key (optional; CTI works in a degraded mode without it).
- `OFFLINE_IP_BLOCKLIST`: path to a newline‑separated list of known‑bad IPs to escalate risk without CTI calls.

## Outputs

- Enriched events: `data/processed/<name>.jsonl` (or `.csv` with `--format csv`).
- Reports: `data/processed/reports/report.txt` and `report.md` summarizing activity and suspicious IPs; may include a brief AI note if LLM is enabled.
- CTI cache: `data/cache/cti_cache.json` (auto‑created and reused to minimize network calls).

## Testing

- Run tests: `pytest -q`
- Optional coverage: `pytest --cov=src -q` (if coverage plugin installed).

## Troubleshooting

- `.txt` auto‑detection: the CLI reads a small sample and parses with `parse_line`. If none match, the file is copied as plain text rather than parsed as logs.
- LLM budget exceeded: you’ll see `LLM budget exhausted` in logs; records are still produced with `severity=unknown` and a rationale explaining sampling/gating.
- CTI failures: the pipeline continues with cached/partial data; use `--no-cti` for fully offline runs. Consider `--cti-max` and batching to avoid rate limits.
- No colors or CI: pass `--color never` for consistent, plain output.

## Docs

- Usage guide with more examples: `docs/USAGE.md`
- Principles, strategy, and repo conventions: `AGENTS.md`
- Mindmap/diagram: `ProjectMindmapv0.5.png`
- Project write‑ups: `docs/Final Project - Log Analysis + CTI.pdf`

---

Made with a focus on reliability, scalability, and cost‑awareness.


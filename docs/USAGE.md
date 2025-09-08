Usage

- Create venv: `python -m venv .venv && source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Basic run (log -> enriched events + reports):
  - `python -m src.cli data/raw/access_log.txt --out data/processed --summary --preview 3`
  - Adds `data/processed/access_log.jsonl` and `data/processed/reports/report.txt|md`.
  - Any `.log` file is treated as a log. `.txt` files are auto-detected: if they contain recognizable log lines, they are parsed as logs; otherwise they are copied as plain text. Example: `python -m src.cli data/raw/new_log.txt --out data/processed`.
- Options:
  - `--verbose quiet|normal|max`: control console verbosity (default: `max`).
  - `--no-llm`: disable LLM enrichment (default if no GROQ keys).
  - `--no-cti`: disable CTI lookups (scraping/API); runs offline.
  - `--no-reports`: skip building reports.
  - `--limit N`: process only the first N lines for quick tests.
  - `--format jsonl|csv`: choose output for enriched events.
  - `--color auto|always|never`: terminal color policy.
  - `--llm-group-by none|ip|signature`: group records before LLM calls to reduce requests. `ip` groups by source IP (minimal requests). `signature` groups by `ip+path+status+ua`.
  - `--llm-sample N`: only send N groups to the LLM; non-selected groups are annotated as `severity=unknown` with rationale `LLM sampled out`.
  - `--llm-gate-4xx N`: only send groups with at least N 4xx responses.
  - `--llm-gate-ua`: only send groups with suspicious user-agents.
  - `--group-window SECONDS`: add a time window bucket to grouping to compress bursts (e.g., `60`).
  - `--cti-scope suspicious|all`: look up CTI for only suspicious IPs (based on 4xx and UA) or all IPs.
  - `--cti-max N`: maximum number of IPs to query for CTI (0=unlimited).
  - `--cti-batch-size N` and `--cti-batch-pause S`: periodically flush cache and pause S seconds between CTI batches.

Environment

- Copy `.env.example` to `.env` and set:
  - `GROQ_API_KEYS` for LLM enrichment (comma-separated supported).
  - `GROQ_MODEL` if you want to change the default.
  - Optional CTI provider keys:
    - `VT_API_KEY` (VirusTotal IP lookups)
    - `OTX_API_KEY` (AlienVault OTX pulses)
    - `GREYNOISE_API_KEY` (GreyNoise community/enterprise)
    - `IPINFO_TOKEN` (org/geo enrichment)

Testing

- Run tests: `pytest -q`
- Measure coverage: `pytest --cov=src -q` (if coverage plugin installed).

Notes

- CTI lookups include AbuseIPDB/Talos/VirusTotal by default, and will also use OTX, GreyNoise, ThreatFox, and IPInfo when keys/network are available. In offline or restricted environments, the tool continues without CTI data.
- Reports summarize overall activity, surface suspicious IPs (CTI risk, 4xx rate, UA flags), and include an optional brief AI anomaly insight when LLM is enabled.

Performance tips

- To avoid rate limits on large logs, prefer `--llm-group-by ip --group-window 60 --llm-gate-4xx 5 --llm-sample 200 --cti-scope suspicious --cti-max 200`.
- For fully offline, fastest runs use `--no-llm --no-cti --no-reports`.
 
Environment variables

- `GROQ_TOKENS_BUDGET`: approximate daily token budget for LLM calls. When reached, enrichment gracefully degrades and continues offline.
- `OFFLINE_IP_BLOCKLIST`: path to a newline-separated list of IPs to treat as high risk without CTI calls.
  - Token accounting uses model‑reported usage when available; otherwise a conservative estimate.
 
Dashboard

- Install UI deps: `pip install -r requirements.txt`
- Run: `streamlit run ui/app.py`
- Select the latest file in `data/processed/` and keep the auto-refresh enabled for near real-time updates while the CLI processes logs.

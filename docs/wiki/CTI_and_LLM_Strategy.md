# CTI + LLM Strategy

Principles
- Offline‑first: deterministic outputs without network
- Group then sample to minimize LLM calls
- Gates on 4xx and suspicious UA
- Strong CTI cache; batch + pause for resilience
- Budget throttle via `GROQ_TOKENS_BUDGET`

LLM
- Grouping: `ip` or `signature` (ip+path+status+ua)
- Sampling: `--llm-sample N` (default 200)
- Gates: `--llm-gate-4xx N`, `--llm-gate-ua`

CTI
- Scope: `--cti-scope suspicious` (default) or `all`
- Caps: `--cti-max`, batching and pause
- Cache: `data/cache/cti_cache.json` reused across runs
- VT/API: defer to shortlist; fail soft when rate‑limited


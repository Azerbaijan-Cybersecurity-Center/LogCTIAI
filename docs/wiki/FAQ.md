# FAQ

Q: Can I run fully offline?
A: Yes — use `--no-llm --no-cti`. Reports remain reproducible; severity is marked `unknown` with rationale.

Q: How to avoid rate limits?
A: Use `--cti-max`, batching flags, and rely on the cache. Prefer grouping + sampling for LLM.

Q: Why are some groups missing LLM notes?
A: They were gated/sampled out or the budget was reached.

Q: Where are results stored?
A: `data/processed/` and `data/processed/reports/`.


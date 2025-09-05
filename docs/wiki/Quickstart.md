# Quickstart

Create env
- `python -m venv .venv && source .venv/bin/activate`
- `pip install -r requirements.txt`

Offline run
- `python -m src.cli data/raw/big.log --out data/processed --no-llm --no-cti --no-reports`

Budgeted run
- `export GROQ_TOKENS_BUDGET=150000`
- `python -m src.cli data/raw/big.log --out data/processed --llm-group-by ip --llm-sample 200 --cti-scope suspicious --cti-max 200 --color never`

Outputs
- `data/processed/*.jsonl|csv`
- `data/processed/reports/*.{txt,md}`
- `data/cache/cti_cache.json`


# CLI Reference

`python -m src.cli <input> --out <dir> [options]`

Core
- `--format {jsonl,csv}`
- `--summary`, `--preview N`
- `--no-llm`, `--no-cti`, `--no-reports`
- `--limit N`, `--color {auto,always,never}`

LLM
- `--llm-group-by {none,ip,signature}`
- `--group-window SECONDS`
- `--llm-sample N`, `--llm-gate-4xx N`, `--llm-gate-ua`

CTI
- `--cti-scope {suspicious,all}`
- `--cti-max N`, `--cti-batch-size N`, `--cti-batch-pause S`

Examples
```bash
python -m src.cli data/raw/access.log --out data/processed --summary --preview 5
python -m src.cli data/raw/big.log --out data/processed \
  --llm-group-by signature --llm-sample 100 --cti-max 100 --summary
```


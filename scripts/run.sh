#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m src.cli data/raw/access_log.txt --out data/processed --limit 50


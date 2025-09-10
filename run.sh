#!/usr/bin/env bash
set -euo pipefail

cmd=${1:-help}

case "$cmd" in
  setup)
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ;;
  ui)
    source .venv/bin/activate
    streamlit run src/ui/streamlit_app.py
    ;;
  scan)
    source .venv/bin/activate
    python -m src.cli scan-ips "${2:-data/sample_ips.txt}" --out data/processed
    ;;
  scan-all)
    source .venv/bin/activate
    python -m src.cli scan-ips "${2:-data/sample_ips.txt}" --out data/processed --cti-max -1 --cti-rate 0.8 --cti-burst 1 --save-every 25
    ;;
  doctor)
    make doctor || true
    ;;
  *)
    echo "Usage: ./run.sh [setup|ui|scan|scan-all|doctor] [file]" ;;
esac


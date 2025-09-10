#!/usr/bin/env bash
set -euo pipefail

if [ -d .venv ]; then
  . .venv/bin/activate
fi

exec streamlit run ui/app.py


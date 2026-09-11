#!/usr/bin/env bash
set -euo pipefail
export FOUNDRY_DIR="$PWD/.render-foundry"
export TOOLS_DIR="$PWD/.render-tools/bin"
export PATH="$FOUNDRY_DIR/bin:$TOOLS_DIR:$HOME/.config/.foundry/bin:$HOME/.local/bin:$PATH"
command -v forge
command -v slither
command -v halmos
command -v osv-scanner
command -v gitleaks
python scripts/live_engine_self_test.py
exec gunicorn --bind 0.0.0.0:"${PORT}" --workers 1 --threads 4 --timeout 120 main:app

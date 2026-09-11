#!/usr/bin/env bash
set -euo pipefail
export FOUNDRY_DIR="$PWD/.render-foundry"
export PATH="$FOUNDRY_DIR/bin:/opt/render/.local/bin:$HOME/.config/.foundry/bin:$HOME/.local/bin:$PATH"
command -v forge
command -v slither
command -v halmos
command -v /opt/render/.local/bin/osv-scanner
command -v /opt/render/.local/bin/gitleaks
python scripts/live_engine_self_test.py
exec gunicorn --bind 0.0.0.0:"${PORT}" --workers 1 --threads 4 --timeout 120 main:app

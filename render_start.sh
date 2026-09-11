#!/usr/bin/env bash
set -euo pipefail
export FOUNDRY_DIR="$PWD/.render-foundry"
export TOOLS_DIR="$PWD/.render-tools/bin"
export ITYFUZZ_DIR="$PWD/.render-ityfuzz"
export PATH="$FOUNDRY_DIR/bin:$TOOLS_DIR:$ITYFUZZ_DIR/bin:$HOME/.config/.foundry/bin:$HOME/.local/bin:$PATH"
command -v forge
command -v slither
command -v halmos
command -v ityfuzz
command -v osv-scanner
command -v gitleaks
nohup python -u scripts/live_engine_self_test.py >/proc/1/fd/1 2>/proc/1/fd/2 </dev/null &
exec gunicorn --bind 0.0.0.0:"${PORT}" --workers 1 --threads 4 --timeout 120 main:app

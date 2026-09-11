#!/usr/bin/env bash
set -euo pipefail
export FOUNDRY_DIR="$PWD/.render-foundry"
export PATH="$FOUNDRY_DIR/bin:$HOME/.config/.foundry/bin:$PATH"
exec gunicorn --bind 0.0.0.0:"${PORT}" --workers 1 --threads 4 --timeout 120 main:app

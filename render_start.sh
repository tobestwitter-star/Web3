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
# Bind the web port first so Render's health/port detector never waits on the
# bounded six-engine self-test. Keep the self-test as a sibling background job.
gunicorn --bind 0.0.0.0:"${PORT}" --workers 1 --threads 4 --timeout 120 main:app &
server_pid=$!
python -u scripts/live_engine_self_test.py >/proc/1/fd/1 2>/proc/1/fd/2 </dev/null &
self_test_pid=$!
wait "$server_pid"
server_status=$?
wait "$self_test_pid" || true
exit "$server_status"

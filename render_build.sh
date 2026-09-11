#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt

export FOUNDRY_DIR="$PWD/.render-foundry"
export PATH="$FOUNDRY_DIR/bin:$PATH"
mkdir -p "$FOUNDRY_DIR/bin"

# foundryup-init honors the project-local install location on Render's Python image.
if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  curl -L https://foundry.paradigm.xyz | bash
fi

if [ -x "$FOUNDRY_DIR/bin/foundryup" ] && [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  "$FOUNDRY_DIR/bin/foundryup"
fi

# Compatibility fallback for installers that use the standard user location.
if [ ! -x "$FOUNDRY_DIR/bin/forge" ] && [ -x "$HOME/.config/.foundry/bin/foundryup" ]; then
  "$HOME/.config/.foundry/bin/foundryup"
  cp -f "$HOME/.config/.foundry/bin"/{forge,cast,anvil,chisel,solar} "$FOUNDRY_DIR/bin/" 2>/dev/null || true
fi

if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  echo "Foundry installation failed; forge is required for execution-backed analysis" >&2
  exit 1
fi

"$FOUNDRY_DIR/bin/forge" --version
command -v slither
slither --version
command -v halmos
halmos --version

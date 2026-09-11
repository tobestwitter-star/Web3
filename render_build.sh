#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt

export FOUNDRY_DIR="$PWD/.render-foundry"
mkdir -p "$FOUNDRY_DIR/bin"
export PATH="$FOUNDRY_DIR/bin:$PATH"

# foundryup installs the toolchain into FOUNDRY_DIR when FOUNDRY_DIR is set.
if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  export FOUNDRY_DIR="$FOUNDRY_DIR"
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.config/.foundry/bin:$PATH"
  "$HOME/.config/.foundry/bin/foundryup"
  mkdir -p "$PWD/.render-foundry/bin"
  cp -f "$HOME/.config/.foundry/bin"/{forge,cast,anvil,chisel,solar} "$PWD/.render-foundry/bin/" 2>/dev/null || true
fi

if [ ! -x "$PWD/.render-foundry/bin/forge" ]; then
  echo "Foundry installation failed; forge is required for execution-backed analysis" >&2
  exit 1
fi

"$PWD/.render-foundry/bin/forge" --version
python -c 'import shutil; print("slither:", shutil.which("slither")); print("halmos:", shutil.which("halmos"))'

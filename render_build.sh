#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt

# Keep the mature EVM engine inside the existing free Python service filesystem.
# The existing Render service remains Python; this avoids requiring a paid or
# replacement service and makes the executable path deterministic at runtime.
export FOUNDRY_DIR="$PWD/.render-foundry"
mkdir -p "$FOUNDRY_DIR"
export PATH="$FOUNDRY_DIR/bin:$PATH"

if [ ! -x "$FOUNDRY_DIR/bin/foundryup" ]; then
  curl -L https://foundry.paradigm.xyz | bash -s -- --install-dir "$FOUNDRY_DIR/bin" || true
fi

# foundryup's installer may not support a custom path on older revisions;
# fall back to its standard user installation and copy the verified binaries.
if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  export PATH="$HOME/.config/.foundry/bin:$PATH"
  curl -L https://foundry.paradigm.xyz | bash
  "$HOME/.config/.foundry/bin/foundryup"
  mkdir -p "$FOUNDRY_DIR/bin"
  cp -f "$HOME/.config/.foundry/bin"/{forge,cast,anvil,chisel,solar} "$FOUNDRY_DIR/bin/" 2>/dev/null || true
fi

if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  echo "Foundry installation failed; forge is required for execution-backed analysis" >&2
  exit 1
fi

"$FOUNDRY_DIR/bin/forge" --version
python -c 'import shutil; print("slither:", shutil.which("slither")); print("halmos:", shutil.which("halmos"))'

#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt

export FOUNDRY_DIR="$PWD/.render-foundry"
export PATH="$FOUNDRY_DIR/bin:$HOME/.local/bin:$PATH"
mkdir -p "$FOUNDRY_DIR/bin" "$HOME/.local/bin"

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

install_osv_scanner() {
  local url='https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64'
  local expected='15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0'
  local tmp="$HOME/.local/bin/osv-scanner.download"
  if [ ! -x "$HOME/.local/bin/osv-scanner" ]; then
    curl -fsSL -o "$tmp" "$url"
    echo "$expected  $tmp" | sha256sum -c -
    install -m 0755 "$tmp" "$HOME/.local/bin/osv-scanner"
    rm -f "$tmp"
  fi
}

install_gitleaks() {
  local url='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz'
  local expected='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
  local tmp="$HOME/.local/bin/gitleaks.tar.gz"
  local extract="$HOME/.local/bin/gitleaks.extract"
  if [ ! -x "$HOME/.local/bin/gitleaks" ]; then
    rm -rf "$extract"
    mkdir -p "$extract"
    curl -fsSL -o "$tmp" "$url"
    echo "$expected  $tmp" | sha256sum -c -
    tar -xzf "$tmp" -C "$extract" gitleaks
    install -m 0755 "$extract/gitleaks" "$HOME/.local/bin/gitleaks"
    rm -rf "$extract" "$tmp"
  fi
}

install_osv_scanner
install_gitleaks

"$FOUNDRY_DIR/bin/forge" --version
command -v slither
slither --version
command -v halmos
halmos --version
command -v osv-scanner
osv-scanner --version
command -v gitleaks
gitleaks version

#!/usr/bin/env bash
set -euo pipefail

python -m pip install -r requirements.txt

export FOUNDRY_DIR="$PWD/.render-foundry"
export TOOLS_DIR="$PWD/.render-tools/bin"
export ITYFUZZ_DIR="$PWD/.render-ityfuzz"
export PATH="$FOUNDRY_DIR/bin:$TOOLS_DIR:$ITYFUZZ_DIR/bin:$HOME/.local/bin:$HOME/.ityfuzz/bin:$PATH"
mkdir -p "$FOUNDRY_DIR/bin" "$TOOLS_DIR" "$ITYFUZZ_DIR/bin"

if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  curl -L https://foundry.paradigm.xyz | bash
fi

if [ -x "$FOUNDRY_DIR/bin/foundryup" ] && [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  "$FOUNDRY_DIR/bin/foundryup"
fi

if [ ! -x "$FOUNDRY_DIR/bin/forge" ] && [ -x "$HOME/.foundry/bin/foundryup" ]; then
  "$HOME/.foundry/bin/foundryup"
  cp -f "$HOME/.foundry/bin"/{forge,cast,anvil,chisel,solar} "$FOUNDRY_DIR/bin/" 2>/dev/null || true
fi

if [ ! -x "$FOUNDRY_DIR/bin/forge" ]; then
  echo "Foundry installation failed; forge is required for execution-backed analysis" >&2
  exit 1
fi

install_ityfuzz() {
  if [ -x "$ITYFUZZ_DIR/bin/ityfuzz" ]; then return 0; fi
  if command -v ityfuzz >/dev/null 2>&1; then
    resolved="$(command -v ityfuzz)"
    if [ "$resolved" != "$ITYFUZZ_DIR/bin/ityfuzz" ]; then cp -f "$resolved" "$ITYFUZZ_DIR/bin/ityfuzz"; fi
    return 0
  fi
  local installer="$TOOLS_DIR/ityfuzz-installer.sh"
  curl -fsSL -o "$installer" https://ity.fuzz.land/
  bash "$installer"
  rm -f "$installer"

  if [ -f "$HOME/.bashrc" ]; then
    # shellcheck disable=SC1090
    source "$HOME/.bashrc" || true
  fi
  if [ -f /opt/render/.bashrc ]; then
    # shellcheck disable=SC1091
    source /opt/render/.bashrc || true
  fi
  if command -v ityfuzzup >/dev/null 2>&1; then
    ityfuzzup
  elif [ -x "$HOME/.ityfuzz/bin/ityfuzzup" ]; then
    "$HOME/.ityfuzz/bin/ityfuzzup"
  fi

  if [ -x "$HOME/.ityfuzz/bin/ityfuzz" ]; then
    cp -f "$HOME/.ityfuzz/bin/ityfuzz" "$ITYFUZZ_DIR/bin/ityfuzz"
  elif [ -x "$HOME/.local/bin/ityfuzz" ]; then
    cp -f "$HOME/.local/bin/ityfuzz" "$ITYFUZZ_DIR/bin/ityfuzz"
  elif command -v ityfuzz >/dev/null 2>&1; then
    resolved="$(command -v ityfuzz)"
    if [ "$resolved" != "$ITYFUZZ_DIR/bin/ityfuzz" ]; then cp -f "$resolved" "$ITYFUZZ_DIR/bin/ityfuzz"; fi
  else
    found="$(find "$HOME" /opt/render -type f -name ityfuzz -perm -u+x 2>/dev/null | head -n 1 || true)"
    if [ -n "$found" ] && [ "$found" != "$ITYFUZZ_DIR/bin/ityfuzz" ]; then cp -f "$found" "$ITYFUZZ_DIR/bin/ityfuzz"; fi
  fi
}

install_ityfuzz
if [ ! -x "$ITYFUZZ_DIR/bin/ityfuzz" ]; then
  echo "ItyFuzz installation failed; real fuzzing integration is required" >&2
  exit 1
fi

install_osv_scanner() {
  local url='https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64'
  local expected='15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0'
  local target="$TOOLS_DIR/osv-scanner"
  local tmp="$TOOLS_DIR/osv-scanner.download"
  if [ ! -x "$target" ]; then
    curl -fsSL -o "$tmp" "$url"
    echo "$expected  $tmp" | sha256sum -c -
    install -m 0755 "$tmp" "$target"
    rm -f "$tmp"
  fi
}

install_gitleaks() {
  local url='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz'
  local expected='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
  local target="$TOOLS_DIR/gitleaks"
  local tmp="$TOOLS_DIR/gitleaks.tar.gz"
  local extract="$TOOLS_DIR/gitleaks.extract"
  if [ ! -x "$target" ]; then
    rm -rf "$extract"
    mkdir -p "$extract"
    curl -fsSL -o "$tmp" "$url"
    echo "$expected  $tmp" | sha256sum -c -
    tar -xzf "$tmp" -C "$extract" gitleaks
    install -m 0755 "$extract/gitleaks" "$target"
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
command -v "$ITYFUZZ_DIR/bin/ityfuzz"
"$ITYFUZZ_DIR/bin/ityfuzz" --version
command -v "$TOOLS_DIR/osv-scanner"
"$TOOLS_DIR/osv-scanner" --version
command -v "$TOOLS_DIR/gitleaks"
"$TOOLS_DIR/gitleaks" version

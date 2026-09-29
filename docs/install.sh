#!/bin/sh
# Ethos installer (Linux x86_64 and macOS Apple Silicon)
#
# Usage:
#   curl -fsSL https://xyzmr114.github.io/ds440-ethos/install.sh | sh
#
# Options (set before running):
#   ETHOS_VERSION=v0.1.0-beta.1     release tag to install
#   ETHOS_INSTALL_DIR=~/.local/bin  where to put the commands
#
# What it does:
#   1. Figures out your operating system and chip type.
#   2. Downloads the matching ready-made Ethos program from GitHub Releases.
#   3. Checks the download is not corrupted (SHA-256 checksum).
#   4. Installs the `ethos`, `tbox`, and `taintbox` commands.
#   If no ready-made program exists for your computer, it builds from source with Rust.

set -eu

REPO="${ETHOS_REPOSITORY:-xyzmr114/ds440-ethos}"
VERSION="${ETHOS_VERSION:-v0.1.0-beta.1}"
INSTALL_DIR="${ETHOS_INSTALL_DIR:-$HOME/.local/bin}"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$1" >&2; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

need curl || fail "curl is required to install Ethos."
need tar  || fail "tar is required to install Ethos."

# ---- Step 1: detect OS and CPU ------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
ARCHIVE=""
SUMS=""
SUFFIX=""

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ARCHIVE="ethos-linux-x86_64-cli.tar.gz"; SUMS="SHA256SUMS-linux.txt" ;;
    esac ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ARCHIVE="ethos-mac-arm64-cli.tar.gz"; SUMS="SHA256SUMS-macos-arm64.txt"; SUFFIX="-arm64" ;;
    esac ;;
  MINGW*|MSYS*|CYGWIN*)
    fail "On Windows, download the installer (.msi or setup .exe) from https://github.com/$REPO/releases" ;;
  *)
    fail "Unsupported operating system: $OS" ;;
esac

say "Detected $OS ($ARCH)"
mkdir -p "$INSTALL_DIR"

sha256() {
  if need sha256sum; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

build_from_source() {
  warn "No ready-made Ethos download for $OS ($ARCH). Building from source instead (takes a few minutes)."
  if ! need cargo && [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
  need cargo || fail "Rust is not installed. Install it with:
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
then open a new terminal and run this installer again."
  BUILD_ROOT="$(mktemp -d)"
  cargo install --git "https://github.com/$REPO" --tag "$VERSION" --locked --root "$BUILD_ROOT" --bin ethos
  mv "$BUILD_ROOT/bin/ethos" "$INSTALL_DIR/ethos"
  rm -rf "$BUILD_ROOT"
  ln -sf "$INSTALL_DIR/ethos" "$INSTALL_DIR/tbox"
  ln -sf "$INSTALL_DIR/ethos" "$INSTALL_DIR/taintbox"
}

if [ -z "$ARCHIVE" ]; then
  build_from_source
else
  # ---- Step 2: download the release ------------------------------------------
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  say "Downloading Ethos $VERSION ($ARCHIVE)"
  curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMP/$ARCHIVE" || fail "Download failed. Check that release $VERSION exists: https://github.com/$REPO/releases"

  # ---- Step 3: verify checksum -----------------------------------------------
  if curl -fsSL "$BASE_URL/$SUMS" -o "$TMP/sums.txt" 2>/dev/null; then
    EXPECTED="$(grep "  $ARCHIVE\$" "$TMP/sums.txt" | cut -d' ' -f1 || true)"
    ACTUAL="$(sha256 "$TMP/$ARCHIVE")"
    if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
      fail "Checksum mismatch: the download may be corrupted. Please try again."
    fi
    [ -n "$EXPECTED" ] && say "Checksum verified"
  else
    warn "Checksum file unavailable; skipping verification."
  fi

  # ---- Step 4: install ---------------------------------------------------------
  tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
  for cmd in ethos tbox taintbox; do
    [ -f "$TMP/$cmd$SUFFIX" ] && install -m 0755 "$TMP/$cmd$SUFFIX" "$INSTALL_DIR/$cmd"
  done
  [ -x "$INSTALL_DIR/ethos" ] || fail "Install failed: ethos binary not found in the download."
fi

say "Installed ethos, tbox, and taintbox to $INSTALL_DIR"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    warn "$INSTALL_DIR is not on your PATH yet. Add this line to ~/.bashrc or ~/.zshrc:"
    printf '    export PATH="%s:$PATH"\n' "$INSTALL_DIR"
    ;;
esac

say "Done! Try:  ethos --help"

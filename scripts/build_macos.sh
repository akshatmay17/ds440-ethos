#!/usr/bin/env bash
# Ethos macOS Build & Packaging Script
# Builds ethos CLI and bundles native macOS .app and .dmg via Tauri v2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/macos"

echo "============================================================"
echo "  Ethos macOS Build & Installer Generator"
echo "============================================================"

# 1. Verify Rust
if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not found in PATH."
    echo "Install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "Or via Homebrew: brew install rust"
    exit 1
fi

mkdir -p "$DIST_DIR"

# 2. Build CLI & Daemon
echo ""
echo "[1/3] Building Standalone CLI & Daemon (ethos)..."
cd "$ROOT_DIR"
cargo build --release --bin ethos
cp "target/release/ethos" "$DIST_DIR/ethos"
chmod +x "$DIST_DIR/ethos"
echo "  -> CLI compiled to $DIST_DIR/ethos"

# 3. Check Tauri CLI & Build Desktop Application & DMG
echo ""
echo "[2/3] Building macOS Desktop App (.app and .dmg)..."
cd "$ROOT_DIR/apps/desktop"
if command -v cargo-tauri &> /dev/null; then
    cargo tauri build
elif command -v tauri &> /dev/null; then
    tauri build
else
    npx --yes @tauri-apps/cli@latest build
fi

BUNDLE_BASE="src-tauri/target/release/bundle"
if [ -d "$BUNDLE_BASE" ]; then
    # Copy DMG
    find "$BUNDLE_BASE/dmg" -name "*.dmg" -exec cp {} "$DIST_DIR/" \; 2>/dev/null || true
    
    # Copy and tar .app
    APP_PATH=$(find "$BUNDLE_BASE/macos" -name "*.app" -maxdepth 1 -type d | head -n 1)
    if [ -n "$APP_PATH" ]; then
        cp -R "$APP_PATH" "$DIST_DIR/"
        tar -czf "$DIST_DIR/Ethos-mac.app.tar.gz" -C "$(dirname "$APP_PATH")" "$(basename "$APP_PATH")"
        echo "  -> Packaged $(basename "$APP_PATH")"
    fi
fi

# 5. Checksums
cd "$DIST_DIR"
rm -f SHA256SUMS.txt
for file in *; do
    if [ -f "$file" ]; then
        shasum -a 256 "$file" >> SHA256SUMS.txt
    fi
done

echo ""
echo "============================================================"
echo "  Build Complete! macOS artifacts staged in:"
echo "  $DIST_DIR"
ls -lh "$DIST_DIR"
echo "============================================================"

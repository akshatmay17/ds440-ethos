#!/usr/bin/env bash
# Ethos Linux Build & Packaging Script
# Builds ethos / tbox CLI and bundles native Linux .deb and .AppImage via Tauri v2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/linux"

echo "============================================================"
echo "  Ethos Linux Build & Package Generator"
echo "============================================================"

# 1. Verify Rust
if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not found in PATH."
    echo "Install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
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

# 3. Check Tauri CLI
echo ""
echo "[2/3] Checking Tauri CLI..."
if ! command -v cargo-tauri &> /dev/null && ! command -v tauri &> /dev/null; then
    echo "Installing tauri-cli v2..."
    cargo install tauri-cli --version "^2.0.0" --locked
fi

# 4. Build Desktop Application (.deb, .AppImage)
echo ""
echo "[3/3] Building Linux Desktop App (.deb, .AppImage)..."
cd "$ROOT_DIR/apps/desktop"

# Check if Tauri system dependencies are available
if command -v dpkg-query &> /dev/null && dpkg-query -W -f='${Status}' libwebkit2gtk-4.1-dev 2>/dev/null | grep -q "install ok installed"; then
    cargo tauri build
    BUNDLE_BASE="src-tauri/target/release/bundle"
    if [ -d "$BUNDLE_BASE" ]; then
        find "$BUNDLE_BASE/deb" -name "*.deb" -exec cp {} "$DIST_DIR/" \; 2>/dev/null || true
        find "$BUNDLE_BASE/appimage" -name "*.AppImage" -exec cp {} "$DIST_DIR/" \; 2>/dev/null || true
        echo "  -> Tauri Linux bundles staged into $DIST_DIR"
    fi
else
    echo "Notice: libwebkit2gtk-4.1-dev not installed locally. Skipping Tauri GUI packaging."
    echo "Install dependencies on Debian/Ubuntu with:"
    echo "  sudo apt update && sudo apt install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf"
fi

# 5. Package Portable Tarball
cd "$DIST_DIR"
tar -czf "ethos-linux-x64-cli.tar.gz" ethos

# 6. Generate Checksums
rm -f SHA256SUMS.txt
for file in *; do
    if [ -f "$file" ]; then
        sha256sum "$file" >> SHA256SUMS.txt
    fi
done

echo ""
echo "============================================================"
echo "  Build Complete! Linux artifacts staged in:"
echo "  $DIST_DIR"
ls -lh "$DIST_DIR"
echo "============================================================"

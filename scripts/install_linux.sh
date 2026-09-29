#!/usr/bin/env bash

set -euo pipefail

REPOSITORY="${ETHOS_REPOSITORY:-xyzmr114/ds440-ethos}"
VERSION="${1:-${ETHOS_VERSION:-v0.1.0-beta.1}}"
INSTALL_DIR="${ETHOS_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -m)" in
  x86_64|amd64)
    ARCHIVE="ethos-linux-x86_64-cli.tar.gz"
    ;;
  *)
    echo "Ethos beta currently supports Linux x86_64 only." >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to install Ethos." >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "tar is required to install Ethos." >&2
  exit 1
fi

BASE_URL="${ETHOS_BASE_URL:-https://github.com/${REPOSITORY}/releases/download/${VERSION}}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Downloading Ethos ${VERSION} for Linux x86_64..."
curl --fail --location --silent --show-error \
  "${BASE_URL}/${ARCHIVE}" \
  --output "${TEMP_DIR}/${ARCHIVE}"

if curl --fail --location --silent --show-error \
  "${BASE_URL}/SHA256SUMS-linux.txt" \
  --output "${TEMP_DIR}/SHA256SUMS-linux.txt"; then
  (
    cd "$TEMP_DIR"
    grep "  ${ARCHIVE}$" SHA256SUMS-linux.txt | sha256sum --check --strict -
  )
else
  echo "Warning: Linux checksum file was unavailable. Continuing without verification." >&2
fi

tar -xzf "${TEMP_DIR}/${ARCHIVE}" -C "$TEMP_DIR"
mkdir -p "$INSTALL_DIR"
install -m 0755 "${TEMP_DIR}/ethos" "${INSTALL_DIR}/ethos"
ln -sf "${INSTALL_DIR}/ethos" "${INSTALL_DIR}/tbox"

echo "Installed Ethos commands to ${INSTALL_DIR}."
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Add ${INSTALL_DIR} to PATH before running ethos." ;;
esac

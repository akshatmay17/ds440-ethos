#!/usr/bin/env sh
set -eu
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
command -v lockit >/dev/null 2>&1 || { echo 'Install Lockit first; see docs/lockit-integration.md.' >&2; exit 1; }
[ -d .lockit ] || { echo 'Initialize and authorize the Lockit project first.' >&2; exit 1; }
exec lockit run -- cargo run -- "$@"

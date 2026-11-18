#!/usr/bin/env bash
# Install the pinned ChainGuard toolchain: Syft, Grype, Trivy (release binaries) and cdxgen (npm).
#
# Usage:  scripts/install-tools.sh [BIN_DIR]
#         BIN_DIR defaults to /usr/local/bin if writable, otherwise ~/.local/bin.
# Needs:  curl, and npm (Node.js 20+) for cdxgen. Linux or macOS; on Windows, run inside WSL2.
#
# Versions come from src/chainguard/toolchain.env. The install scripts are fetched from the
# same release tag as the binary, and they verify the release checksums before installing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=src/chainguard/toolchain.env
source "$ROOT/src/chainguard/toolchain.env"

BIN="${1:-}"
if [[ -z "$BIN" ]]; then
  if [[ -w /usr/local/bin ]]; then BIN=/usr/local/bin; else BIN="$HOME/.local/bin"; fi
fi
mkdir -p "$BIN"

need() { command -v "$1" > /dev/null || { echo "error: '$1' is required but not installed" >&2; exit 1; }; }
need curl
need npm

echo "Installing the pinned toolchain into $BIN"
curl -sSfL "https://raw.githubusercontent.com/anchore/syft/v${SYFT_VERSION}/install.sh" \
  | sh -s -- -b "$BIN" "v${SYFT_VERSION}"
curl -sSfL "https://raw.githubusercontent.com/anchore/grype/v${GRYPE_VERSION}/install.sh" \
  | sh -s -- -b "$BIN" "v${GRYPE_VERSION}"
curl -sSfL "https://raw.githubusercontent.com/aquasecurity/trivy/v${TRIVY_VERSION}/contrib/install.sh" \
  | sh -s -- -b "$BIN" "v${TRIVY_VERSION}"
npm install -g --no-fund --no-audit "@cyclonedx/cdxgen@${CDXGEN_VERSION}"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "note: add $BIN to your PATH" ;;
esac
echo "Done. Check with: chainguard tools"

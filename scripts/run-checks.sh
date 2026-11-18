#!/usr/bin/env bash
# Run on your machine the checks that CI's lint and test jobs run, and report which pass.
#
# Usage:  scripts/run-checks.sh [--offline]
# Needs:  pip install -e ".[dev]"   (ruff and pytest). No scanner or Docker needed.
#         --offline skips the one check that asks OSV.dev for advisories.
#
# Keep this in step with the "lint" and "tests" jobs of .github/workflows/ci.yml. CI is the reference. The jobs that
# need Docker (the smoke scan and the GitHub Action) run only in CI.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
export PYTHONDONTWRITEBYTECODE=1

pytest_args=(-q)
if [[ "${1:-}" == "--offline" ]]; then pytest_args+=(--offline); fi

failed=()
run() {
  local label="$1"
  shift
  if "$@" > /tmp/chainguard-check.out 2>&1; then
    printf '  ok    %s\n' "$label"
  else
    printf '  FAIL  %s\n' "$label"
    sed 's/^/        /' /tmp/chainguard-check.out | tail -12
    failed+=("$label")
  fi
}

echo "Code"
run "ruff check" ruff check src tests
run "ruff format" ruff format --check src tests
run "entry point" chainguard --version

echo "Tests"
run "pytest (one test per script in tests/checks/)" python3 -m pytest "${pytest_args[@]}"

echo
if [[ ${#failed[@]} -eq 0 ]]; then
  echo "All checks passed."
else
  echo "${#failed[@]} failed: ${failed[*]}"
  exit 1
fi

#!/bin/bash
#
# Architecture Compliance Checker
#
# Addresses PENDING-006: Architecture Compliance Remediation
# Checks for architectural violations

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ARCHITECTURE_CHECKER="$REPO_ROOT/scripts/architecture-checker.js"

if [ ! -x "$ARCHITECTURE_CHECKER" ]; then
  echo "Architecture checker script missing or not executable: $ARCHITECTURE_CHECKER" >&2
  exit 1
fi

echo "========================================"
echo "Architecture Compliance Checker"
echo "========================================"
echo "Running direct HTTP + message bus guardrails..."

echo ""
node "$ARCHITECTURE_CHECKER"
STATUS=$?

echo ""
echo "========================================"
if [ $STATUS -eq 0 ]; then
  echo -e "\033[0;32m✓ All architecture guardrails satisfied\033[0m"
else
  echo -e "\033[0;31m✗ Architecture guardrails violated\033[0m"
fi

exit $STATUS

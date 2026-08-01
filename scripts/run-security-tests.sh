#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

"$PROJECT_ROOT/scripts/run-sanitizers.sh"
"$PROJECT_ROOT/scripts/run-fuzz-smoke.sh"

echo
echo "SecureCore security-testing pipeline completed."

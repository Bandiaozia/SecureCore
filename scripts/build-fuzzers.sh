#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if ! command -v clang++ >/dev/null 2>&1; then
    echo "clang++ is required to build libFuzzer targets." >&2
    exit 1
fi

JOBS="${SECURECORE_BUILD_JOBS:-$(nproc)}"

cmake --preset fuzz-clang
cmake --build --preset fuzz-clang --parallel "$JOBS"

echo "Fuzz targets built in build-fuzz/fuzzers."

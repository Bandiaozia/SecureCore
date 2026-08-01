#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <cxx-compiler> <build-type> <build-directory>" >&2
    exit 2
fi

CXX_COMPILER="$1"
BUILD_TYPE="$2"
BUILD_DIRECTORY="$3"

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

case "$BUILD_TYPE" in
    Debug|Release|RelWithDebInfo)
        ;;
    *)
        echo "Unsupported build type: $BUILD_TYPE" >&2
        exit 2
        ;;
esac

cmake \
    -S . \
    -B "$BUILD_DIRECTORY" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_CXX_COMPILER="$CXX_COMPILER" \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DBUILD_TESTING=ON

cmake \
    --build "$BUILD_DIRECTORY" \
    --parallel "${SECURECORE_BUILD_JOBS:-$(nproc)}"

ctest \
    --test-dir "$BUILD_DIRECTORY" \
    --output-on-failure \
    --no-tests=error

"$BUILD_DIRECTORY/secure-server" --version
"$BUILD_DIRECTORY/secure-admin" --version

ccache --show-stats

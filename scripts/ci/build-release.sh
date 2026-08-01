#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <version> <output-directory>" >&2
    exit 2
fi

VERSION="${1#v}"
OUTPUT_DIRECTORY="$2"

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

COMMIT="${SECURECORE_RELEASE_COMMIT:-$(git rev-parse HEAD)}"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$COMMIT")}" 
BUILD_DIRECTORY="build-release"

rm -rf "$BUILD_DIRECTORY" "$OUTPUT_DIRECTORY"

export SOURCE_DATE_EPOCH="$SOURCE_EPOCH"

cmake \
    -S . \
    -B "$BUILD_DIRECTORY" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="${CXX:-g++}" \
    -DBUILD_TESTING=OFF \
    -DSECURECORE_VERSION_OVERRIDE="$VERSION" \
    -DSECURECORE_GIT_COMMIT="$COMMIT" \
    "-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -ffile-prefix-map=$PROJECT_ROOT=. -fdebug-prefix-map=$PROJECT_ROOT=."

cmake \
    --build "$BUILD_DIRECTORY" \
    --parallel "${SECURECORE_BUILD_JOBS:-$(nproc)}"

scripts/ci/package-release.sh \
    "$BUILD_DIRECTORY" \
    "$OUTPUT_DIRECTORY" \
    "$VERSION"

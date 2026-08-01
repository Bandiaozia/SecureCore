#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <build-directory> <output-directory> <version>" >&2
    exit 2
fi

BUILD_DIRECTORY="$1"
OUTPUT_DIRECTORY="$2"
VERSION="${3#v}"

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "Invalid release version: $VERSION" >&2
    exit 2
fi

for binary in secure-server secure-admin; do
    if [[ ! -x "$BUILD_DIRECTORY/$binary" ]]; then
        echo "Missing release binary: $BUILD_DIRECTORY/$binary" >&2
        exit 1
    fi
done

COMMIT="${SECURECORE_RELEASE_COMMIT:-$(git rev-parse HEAD)}"
SOURCE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$COMMIT")}" 
ARCH="${SECURECORE_RELEASE_ARCH:-$(uname -m)}"
PLATFORM="linux-${ARCH}"
PACKAGE_NAME="SecureCore-${VERSION}-${PLATFORM}"
STAGING_ROOT="$OUTPUT_DIRECTORY/staging"
STAGING_DIRECTORY="$STAGING_ROOT/$PACKAGE_NAME"
ARCHIVE="$OUTPUT_DIRECTORY/$PACKAGE_NAME.tar.gz"
CHECKSUM="$ARCHIVE.sha256"

rm -rf "$OUTPUT_DIRECTORY"
mkdir -p \
    "$STAGING_DIRECTORY/bin" \
    "$STAGING_DIRECTORY/configs" \
    "$STAGING_DIRECTORY/docs"

install -m 0755 \
    "$BUILD_DIRECTORY/secure-server" \
    "$STAGING_DIRECTORY/bin/secure-server"

install -m 0755 \
    "$BUILD_DIRECTORY/secure-admin" \
    "$STAGING_DIRECTORY/bin/secure-admin"

cp -a configs/. "$STAGING_DIRECTORY/configs/"
cp -a docs/. "$STAGING_DIRECTORY/docs/"

for optional_file in README.md LICENSE LICENSE.txt COPYING; do
    if [[ -f "$optional_file" ]]; then
        install -m 0644 "$optional_file" "$STAGING_DIRECTORY/"
    fi
done

SERVER_VERSION="$($BUILD_DIRECTORY/secure-server --version)"
ADMIN_VERSION="$($BUILD_DIRECTORY/secure-admin --version)"
COMPILER_METADATA="$(
    find "$BUILD_DIRECTORY/CMakeFiles" \
        -type f \
        -name CMakeCXXCompiler.cmake \
        -print \
        -quit
)"
COMPILER_ID="unknown"
COMPILER_VERSION="unknown"

if [[ -n "$COMPILER_METADATA" ]]; then
    COMPILER_ID="$(
        sed -n 's/^set(CMAKE_CXX_COMPILER_ID "\([^"]*\)")/\1/p' \
            "$COMPILER_METADATA" \
            | head -n 1
    )"
    COMPILER_VERSION="$(
        sed -n 's/^set(CMAKE_CXX_COMPILER_VERSION "\([^"]*\)")/\1/p' \
            "$COMPILER_METADATA" \
            | head -n 1
    )"
fi

COMPILER_ID="${COMPILER_ID:-unknown}"
COMPILER_VERSION="${COMPILER_VERSION:-unknown}"

jq -n \
    --arg name "SecureCore" \
    --arg version "$VERSION" \
    --arg commit "$COMMIT" \
    --arg platform "$PLATFORM" \
    --arg build_type "Release" \
    --arg compiler_id "$COMPILER_ID" \
    --arg compiler_version "$COMPILER_VERSION" \
    --arg server_version "$SERVER_VERSION" \
    --arg admin_version "$ADMIN_VERSION" \
    --argjson source_date_epoch "$SOURCE_EPOCH" \
    '{
        name: $name,
        version: $version,
        git_commit: $commit,
        platform: $platform,
        build_type: $build_type,
        compiler: {
            id: $compiler_id,
            version: $compiler_version
        },
        source_date_epoch: $source_date_epoch,
        binaries: {
            server: $server_version,
            admin: $admin_version
        }
    }' \
    > "$STAGING_DIRECTORY/BUILD_INFO.json"

if ! command -v readelf >/dev/null 2>&1; then
    echo "readelf is required to generate a deterministic dependency manifest." >&2
    exit 1
fi

write_direct_dependencies() {
    local label="$1"
    local binary="$2"

    printf '%s\n' "$label"

    LC_ALL=C readelf --dynamic "$binary" \
        | sed -n \
            's/.*Shared library: \[\([^]]*\)\].*/  \1/p' \
        | LC_ALL=C sort -u
}

{
    write_direct_dependencies \
        "secure-server" \
        "$BUILD_DIRECTORY/secure-server"

    echo

    write_direct_dependencies \
        "secure-admin" \
        "$BUILD_DIRECTORY/secure-admin"
} > "$STAGING_DIRECTORY/DEPENDENCIES.txt"

find "$STAGING_DIRECTORY" \
    -exec touch --no-dereference --date="@$SOURCE_EPOCH" {} +

mkdir -p "$OUTPUT_DIRECTORY"

tar \
    --sort=name \
    --format=posix \
    --pax-option=delete=atime,delete=ctime \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --mtime="@$SOURCE_EPOCH" \
    -C "$STAGING_ROOT" \
    -cf - \
    "$PACKAGE_NAME" \
    | gzip -n -9 > "$ARCHIVE"

(
    cd "$OUTPUT_DIRECTORY"
    sha256sum "$(basename "$ARCHIVE")" \
        > "$(basename "$CHECKSUM")"
)

rm -rf "$STAGING_ROOT"

printf '%s\n' "$ARCHIVE"
printf '%s\n' "$CHECKSUM"

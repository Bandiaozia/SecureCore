#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

git diff --check

find scripts tests \
    -type f \
    -name '*.sh' \
    -print0 \
    | xargs -0 -r bash -n

python_files=()
while IFS= read -r -d '' file; do
    python_files+=("$file")
done < <(
    find scripts tests \
        -type f \
        -name '*.py' \
        -print0
)

if ((${#python_files[@]} > 0)); then
    PYTHONDONTWRITEBYTECODE=1 \
        python3 -m py_compile "${python_files[@]}"
fi

find scripts tests \
    -type d \
    -name __pycache__ \
    -prune \
    -exec rm -rf {} +

ruby -e '
require "yaml"
Dir[".github/**/*.yml", ".github/**/*.yaml"].sort.each do |path|
  YAML.load_file(path, aliases: true)
  puts "validated #{path}"
end
'

cmake --list-presets

cmake \
    -S . \
    -B build-ci-validate \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTING=OFF

cmake --build build-ci-validate --parallel 2

./build-ci-validate/secure-server --version
./build-ci-validate/secure-admin --version

echo "Repository checks passed."

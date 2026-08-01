#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "===== Operating system ====="
uname -a
echo

echo "===== Compilers ====="
c++ --version 2>/dev/null | head -n 1 || true
for compiler in clang++-21 clang++-20 clang++-19 clang++-18 clang++; do
    if command -v "$compiler" >/dev/null 2>&1; then
        "$compiler" --version | head -n 1
    fi
done
echo

echo "===== Virtual address settings ====="
for key in \
    kernel.randomize_va_space \
    vm.legacy_va_layout \
    vm.mmap_rnd_bits \
    vm.mmap_rnd_compat_bits
do
    printf '%s=' "$key"
    sysctl -n "$key" 2>/dev/null || echo "unavailable"
done
echo

if [[ ! -x build-tsan/securecore-worker-pool-test ]]; then
    echo "build-tsan/securecore-worker-pool-test is missing."
    echo "Run: cmake --preset tsan && cmake --build --preset tsan"
    exit 1
fi

normal_log="$(mktemp)"
no_aslr_log="$(mktemp)"
trap 'rm -f "$normal_log" "$no_aslr_log"' EXIT

echo "===== Normal TSan probe ====="
set +e
TSAN_OPTIONS='halt_on_error=1' \
    build-tsan/securecore-worker-pool-test \
    >"$normal_log" 2>&1
normal_status=$?
set -e
cat "$normal_log"
echo "exit_status=$normal_status"
echo

if command -v setarch >/dev/null 2>&1; then
    echo "===== Per-process setarch -R probe ====="
    set +e
    setarch "$(uname -m)" -R \
        env TSAN_OPTIONS='halt_on_error=1' \
        build-tsan/securecore-worker-pool-test \
        >"$no_aslr_log" 2>&1
    no_aslr_status=$?
    set -e
    cat "$no_aslr_log"
    echo "exit_status=$no_aslr_status"
else
    echo "setarch is unavailable."
fi

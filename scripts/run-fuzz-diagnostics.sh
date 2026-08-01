#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

"$PROJECT_ROOT/scripts/build-fuzzers.sh"

DIAGNOSTIC_ROOT="build-fuzz/diagnostic-corpus"
rm -rf "$DIAGNOSTIC_ROOT"
mkdir -p "$DIAGNOSTIC_ROOT"

find_llvm_symbolizer() {
    local candidate
    local resolved

    for candidate in \
        llvm-symbolizer-21 \
        llvm-symbolizer-20 \
        llvm-symbolizer-19 \
        llvm-symbolizer-18 \
        llvm-symbolizer
    do
        resolved="$(command -v "$candidate" 2>/dev/null || true)"
        if [[ -n "$resolved" ]]; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done

    return 1
}

LLVM_SYMBOLIZER="$(find_llvm_symbolizer || true)"

run_diagnostic() {
    local executable="$1"
    local corpus="$2"
    local max_length="$3"
    local run_corpus="$DIAGNOSTIC_ROOT/$corpus"
    local -a environment_args

    mkdir -p "$run_corpus"
    cp -a "fuzz/corpus/$corpus/." "$run_corpus/"

    environment_args=(
        "ASAN_OPTIONS=${SECURECORE_FUZZ_ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1}"
        "UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
    )

    if [[ -n "$LLVM_SYMBOLIZER" ]]; then
        environment_args+=(
            "ASAN_SYMBOLIZER_PATH=$LLVM_SYMBOLIZER"
            "LLVM_SYMBOLIZER_PATH=$LLVM_SYMBOLIZER"
        )
    fi

    echo
    echo "===== $executable diagnostic ====="

    env "${environment_args[@]}" \
    /usr/bin/time \
        -f 'elapsed=%e sec max_rss=%M KB' \
        "build-fuzz/fuzzers/$executable" \
            "$run_corpus" \
            -runs=1000 \
            -timeout=2 \
            -max_len="$max_length" \
            -reduce_inputs=0 \
            -detect_leaks=0 \
            -print_funcs=0 \
            -print_pcs=0 \
            -verbosity=1 \
            -rss_limit_mb=1024 \
            -print_final_stats=1
}

run_diagnostic securecore-fuzz-query query 4096
run_diagnostic securecore-fuzz-proxy-headers proxy 4096
run_diagnostic securecore-fuzz-cors cors 2048
run_diagnostic securecore-fuzz-json-validation json 4096
run_diagnostic securecore-fuzz-request-id request_id 512
run_diagnostic securecore-fuzz-router router 4096

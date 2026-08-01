#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

"$PROJECT_ROOT/scripts/build-fuzzers.sh"

SECONDS_PER_TARGET="${SECURECORE_FUZZ_SECONDS:-5}"
ARTIFACT_ROOT="build-fuzz/artifacts"
SMOKE_CORPUS_ROOT="build-fuzz/smoke-corpus"
HARD_GRACE_SECONDS="${SECURECORE_FUZZ_HARD_GRACE_SECONDS:-20}"

if ! [[ "$SECONDS_PER_TARGET" =~ ^[1-9][0-9]*$ ]]; then
    echo "SECURECORE_FUZZ_SECONDS must be a positive integer." >&2
    exit 2
fi

if ! [[ "$HARD_GRACE_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "SECURECORE_FUZZ_HARD_GRACE_SECONDS must be a positive integer." >&2
    exit 2
fi

find_llvm_symbolizer() {
    local candidate
    local resolved

    if [[ -n "${SECURECORE_LLVM_SYMBOLIZER:-}" ]]; then
        if [[ -x "$SECURECORE_LLVM_SYMBOLIZER" ]]; then
            printf '%s\n' "$SECURECORE_LLVM_SYMBOLIZER"
            return 0
        fi

        echo "SECURECORE_LLVM_SYMBOLIZER is not executable: $SECURECORE_LLVM_SYMBOLIZER" >&2
        return 1
    fi

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

rm -rf "$SMOKE_CORPUS_ROOT" "$ARTIFACT_ROOT"
mkdir -p "$SMOKE_CORPUS_ROOT" "$ARTIFACT_ROOT"

run_target() {
    local executable="$1"
    local corpus="$2"
    local max_length="$3"
    local run_corpus="$SMOKE_CORPUS_ROOT/$corpus"
    local hard_limit=$((SECONDS_PER_TARGET + HARD_GRACE_SECONDS))
    local status
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
    echo "===== $executable ====="
    echo "budget=${SECONDS_PER_TARGET}s hard_limit=${hard_limit}s max_len=${max_length} leak_detection=off print_funcs=off"
    if [[ -n "$LLVM_SYMBOLIZER" ]]; then
        echo "symbolizer=$LLVM_SYMBOLIZER"
    else
        echo "symbolizer=not-found"
    fi

    # Function-name printing is disabled because libFuzzer may invoke an
    # incompatible or blocked external symbolizer when it discovers a new
    # function. That can stop the mutation loop at "NEW_FUNC[...]:", even
    # though the target input itself returns normally. ASan/UBSan reporting
    # remains enabled and uses the explicitly selected symbolizer when found.
    set +e
    timeout \
        --signal=TERM \
        --kill-after=5s \
        "${hard_limit}s" \
        env "${environment_args[@]}" \
        "build-fuzz/fuzzers/$executable" \
            "$run_corpus" \
            -artifact_prefix="$ARTIFACT_ROOT/$executable-" \
            -max_total_time="$SECONDS_PER_TARGET" \
            -timeout=2 \
            -max_len="$max_length" \
            -reduce_inputs=0 \
            -detect_leaks=0 \
            -print_funcs=0 \
            -print_pcs=0 \
            -verbosity=1 \
            -rss_limit_mb=1024 \
            -print_final_stats=1
    status=$?
    set -e

    if [[ $status -eq 124 || $status -eq 137 ]]; then
        echo "$executable exceeded the ${hard_limit}s hard runtime limit." >&2
        echo "The target did not return control to libFuzzer within the wall-clock budget." >&2
        return 1
    fi

    if [[ $status -ne 0 ]]; then
        echo "$executable failed with exit status $status." >&2
        return "$status"
    fi
}

run_target securecore-fuzz-query query 4096
run_target securecore-fuzz-proxy-headers proxy 4096
run_target securecore-fuzz-cors cors 2048
run_target securecore-fuzz-json-validation json 4096
run_target securecore-fuzz-request-id request_id 512
run_target securecore-fuzz-router router 4096

echo
echo "All libFuzzer smoke targets passed."

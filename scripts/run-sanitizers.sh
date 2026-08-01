#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

JOBS="${SECURECORE_BUILD_JOBS:-$(nproc)}"
TSAN_TEST_REGEX='securecore-(worker-pool-unit|metrics-unit|database-pool-unit|graceful-shutdown-unit|auth-abuse-unit|security-parser-corpus)'
TSAN_OPTIONS_VALUE="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1:history_size=7}"
REQUIRE_TSAN="${SECURECORE_REQUIRE_TSAN:-0}"
SANITIZER_MODE="${SECURECORE_SANITIZER_MODE:-all}"

temporary_files=()

cleanup() {
    if ((${#temporary_files[@]} > 0)); then
        rm -f -- "${temporary_files[@]}"
    fi
}
trap cleanup EXIT

new_temp_file() {
    local file
    file="$(mktemp)"
    temporary_files+=("$file")
    printf '%s\n' "$file"
}

run_asan_ubsan() {
    cmake --preset asan-ubsan
    cmake --build --preset asan-ubsan --parallel "$JOBS"

    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:strict_string_checks=1:check_initialization_order=1}" \
    UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
    ctest \
        --test-dir build-asan-ubsan \
        --output-on-failure

    echo
    echo "ASan/UBSan full suite passed."
}

configure_gcc_tsan() {
    cmake --preset tsan
    cmake --build --preset tsan --parallel "$JOBS"
}

run_tsan_probe() {
    local build_dir="$1"
    local mode="$2"
    local output_file="$3"
    local executable="$build_dir/securecore-worker-pool-test"

    if [[ ! -x "$executable" ]]; then
        printf 'TSan probe executable not found: %s\n' "$executable" >"$output_file"
        return 127
    fi

    case "$mode" in
        normal)
            env \
                TSAN_OPTIONS="$TSAN_OPTIONS_VALUE" \
                "$executable" \
                >"$output_file" 2>&1
            ;;
        no-aslr)
            setarch "$(uname -m)" -R \
                env TSAN_OPTIONS="$TSAN_OPTIONS_VALUE" \
                "$executable" \
                >"$output_file" 2>&1
            ;;
        *)
            printf 'Unknown TSan probe mode: %s\n' "$mode" >"$output_file"
            return 2
            ;;
    esac
}

run_tsan_ctest() {
    local build_dir="$1"
    local mode="$2"

    case "$mode" in
        normal)
            env \
                TSAN_OPTIONS="$TSAN_OPTIONS_VALUE" \
                ctest \
                    --test-dir "$build_dir" \
                    --output-on-failure \
                    -R "$TSAN_TEST_REGEX"
            ;;
        no-aslr)
            setarch "$(uname -m)" -R \
                env TSAN_OPTIONS="$TSAN_OPTIONS_VALUE" \
                ctest \
                    --test-dir "$build_dir" \
                    --output-on-failure \
                    -R "$TSAN_TEST_REGEX"
            ;;
        *)
            echo "Unknown TSan test mode: $mode" >&2
            return 2
            ;;
    esac
}

is_shadow_mapping_failure() {
    local output_file="$1"

    grep -Eq \
        'ThreadSanitizer: unexpected memory mapping|ThreadSanitizer can not mmap the shadow memory|Shadow memory range interleaves' \
        "$output_file"
}

find_clang_tsan_compiler() {
    local candidate
    local resolved
    local version_text
    local major

    if [[ -n "${SECURECORE_TSAN_CXX:-}" ]]; then
        if command -v "$SECURECORE_TSAN_CXX" >/dev/null 2>&1; then
            command -v "$SECURECORE_TSAN_CXX"
            return 0
        fi

        echo "SECURECORE_TSAN_CXX was set but is not executable: $SECURECORE_TSAN_CXX" >&2
        return 1
    fi

    for candidate in clang++-21 clang++-20 clang++-19 clang++-18 clang++; do
        resolved="$(command -v "$candidate" 2>/dev/null || true)"
        [[ -n "$resolved" ]] || continue

        version_text="$("$resolved" --version 2>/dev/null | head -n 1)"
        major="$(
            sed -nE \
                's/.*clang version ([0-9]+).*/\1/p' \
                <<<"$version_text"
        )"

        if [[ "$major" =~ ^[0-9]+$ ]] && ((major >= 18)); then
            printf '%s\n' "$resolved"
            return 0
        fi
    done

    return 1
}

configure_clang_tsan() {
    local compiler="$1"
    local build_dir="build-tsan-clang"

    rm -rf "$build_dir"

    cmake \
        -S . \
        -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_TESTING=ON \
        -DSECURECORE_SANITIZER=thread \
        -DSECURECORE_BUILD_FUZZERS=OFF \
        -DCMAKE_CXX_COMPILER="$compiler"

    cmake \
        --build "$build_dir" \
        --parallel "$JOBS"
}

print_tsan_environment() {
    echo
    echo "===== TSan environment ====="
    uname -a || true
    printf 'GCC: '
    c++ --version 2>/dev/null | head -n 1 || echo "unavailable"

    if command -v clang++ >/dev/null 2>&1; then
        printf 'Clang: '
        clang++ --version 2>/dev/null | head -n 1 || true
    fi

    for key in \
        kernel.randomize_va_space \
        vm.legacy_va_layout \
        vm.mmap_rnd_bits \
        vm.mmap_rnd_compat_bits
    do
        printf '%s=' "$key"
        sysctl -n "$key" 2>/dev/null || echo "unavailable"
    done
}

handle_tsan_unavailable() {
    local last_output="$1"

    print_tsan_environment

    echo
    echo "ThreadSanitizer could not reserve its shadow-memory address space."
    echo "This is a compiler/runtime/kernel compatibility failure; the focused tests did not start."
    echo "Last TSan output:"
    sed -n '1,120p' "$last_output"

    if [[ "$REQUIRE_TSAN" == "1" ]]; then
        echo
        echo "SECURECORE_REQUIRE_TSAN=1, treating unavailable TSan as a failure."
        return 1
    fi

    echo
    echo "TSan was SKIPPED, not passed."
    echo "ASan/UBSan results remain valid."
    echo "Install Clang 18 or newer, or run TSan on a compatible kernel/CI runner."
    echo "Use SECURECORE_REQUIRE_TSAN=1 in CI when skipping is unacceptable."
    return 0
}

run_tsan() {
    local output
    local compiler

    configure_gcc_tsan

    output="$(new_temp_file)"
    if run_tsan_probe build-tsan normal "$output"; then
        run_tsan_ctest build-tsan normal
        echo
        echo "Focused TSan suite passed with the default compiler."
        return 0
    fi

    if ! is_shadow_mapping_failure "$output"; then
        echo "TSan probe failed for a reason other than shadow-memory mapping:" >&2
        cat "$output" >&2
        return 1
    fi

    echo
    echo "Default TSan runtime hit an address-space mapping conflict."

    if command -v setarch >/dev/null 2>&1; then
        local no_aslr_output
        no_aslr_output="$(new_temp_file)"

        if run_tsan_probe build-tsan no-aslr "$no_aslr_output"; then
            echo "Per-process setarch -R workaround is supported on this machine."
            run_tsan_ctest build-tsan no-aslr
            echo
            echo "Focused TSan suite passed with the per-process setarch -R workaround."
            return 0
        fi

        if ! is_shadow_mapping_failure "$no_aslr_output"; then
            echo "setarch -R started TSan, but the probe found a test/runtime failure:" >&2
            cat "$no_aslr_output" >&2
            return 1
        fi

        output="$no_aslr_output"
    fi

    compiler="$(find_clang_tsan_compiler || true)"
    if [[ -n "$compiler" ]]; then
        echo
        echo "Retrying TSan with: $compiler"
        configure_clang_tsan "$compiler"

        local clang_output
        clang_output="$(new_temp_file)"

        if run_tsan_probe build-tsan-clang normal "$clang_output"; then
            run_tsan_ctest build-tsan-clang normal
            echo
            echo "Focused TSan suite passed with $compiler."
            return 0
        fi

        if ! is_shadow_mapping_failure "$clang_output"; then
            echo "Clang TSan started, but the probe found a test/runtime failure:" >&2
            cat "$clang_output" >&2
            return 1
        fi

        output="$clang_output"
    fi

    handle_tsan_unavailable "$output"
}

case "$SANITIZER_MODE" in
    all)
        run_asan_ubsan
        run_tsan
        ;;
    asan-ubsan)
        run_asan_ubsan
        ;;
    tsan)
        run_tsan
        ;;
    *)
        echo "SECURECORE_SANITIZER_MODE must be all, asan-ubsan, or tsan." >&2
        exit 2
        ;;
esac

echo
echo "Sanitizer pipeline completed: $SANITIZER_MODE."

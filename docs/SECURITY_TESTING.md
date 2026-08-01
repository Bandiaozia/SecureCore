# Security testing

SecureCore provides three complementary runtime-testing modes:

- AddressSanitizer and UndefinedBehaviorSanitizer for memory and undefined-behaviour defects;
- ThreadSanitizer for data races in concurrency-heavy components;
- Clang libFuzzer targets for parsers and request-boundary code.

These builds use separate directories and do not modify the normal `build/` directory.

## AddressSanitizer and UndefinedBehaviorSanitizer

```bash
cmake --preset asan-ubsan
cmake --build --preset asan-ubsan
ctest --preset asan-ubsan
```

The preset instruments the library, server, administrator tool, and tests. It enables leak detection, immediate failure, stack traces, and undefined-behaviour checks.

## ThreadSanitizer

```bash
cmake --preset tsan
cmake --build --preset tsan

TSAN_OPTIONS='halt_on_error=1:second_deadlock_stack=1' \
ctest --test-dir build-tsan --output-on-failure \
  -R 'securecore-(worker-pool-unit|metrics-unit|database-pool-unit|graceful-shutdown-unit|auth-abuse-unit|security-parser-corpus)'
```

The default script runs a focused TSan suite. External libraries such as OpenSSL and SQLite may contain code that was not built with TSan, so the focused suite prioritizes SecureCore-owned concurrency code and reduces unrelated noise.

Run both sanitizer modes with:

```bash
scripts/run-sanitizers.sh
```

## libFuzzer

Install Clang on Ubuntu:

```bash
sudo apt install clang
```

Build fuzzers:

```bash
scripts/build-fuzzers.sh
```

Targets are written to `build-fuzz/fuzzers/`:

- `securecore-fuzz-query`
- `securecore-fuzz-proxy-headers`
- `securecore-fuzz-cors`
- `securecore-fuzz-json-validation`
- `securecore-fuzz-request-id`
- `securecore-fuzz-router`

Run the short seed-corpus smoke suite:

```bash
scripts/run-fuzz-smoke.sh
```

Change the time spent on each target:

```bash
SECURECORE_FUZZ_SECONDS=60 scripts/run-fuzz-smoke.sh
```

Run a single target continuously:

```bash
build-fuzz/fuzzers/securecore-fuzz-proxy-headers \
  fuzz/corpus/proxy \
  -max_len=16384 \
  -timeout=3
```

When libFuzzer finds a crash, it writes an artifact in the current directory. Preserve the artifact, reproduce it against the same binary, and add a minimized form to the matching corpus after fixing the defect.

## One-command pipeline

```bash
scripts/run-security-tests.sh
```

This runs the complete ASan/UBSan suite, a focused TSan suite, and the short libFuzzer smoke suite. It is intentionally separate from normal CTest because sanitizer and fuzz builds take substantially longer.

## Constraints

ASan and TSan must not be enabled together. Fuzzer builds require Clang. Sanitizer results are most useful on a machine where dependencies and SecureCore are compiled for the same architecture and runtime environment.

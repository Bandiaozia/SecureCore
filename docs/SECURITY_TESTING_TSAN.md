## ThreadSanitizer shadow-memory startup failures

A failure such as:

```text
FATAL: ThreadSanitizer: unexpected memory mapping ...
```

happens before the tested program reaches its own test logic. It means the
TSan runtime could not reserve its required shadow-memory address range.

`scripts/run-sanitizers.sh` now distinguishes this environment failure from a
reported data race. It tries, in order:

1. the default GCC TSan build;
2. the same build under a per-process `setarch -R` workaround;
3. Clang 18 or newer, when installed.

The script does not modify global kernel settings.

When no usable TSan runtime is available, local runs report `TSan was SKIPPED,
not passed` and continue after the valid ASan/UBSan result. Strict CI can
require TSan with:

```bash
SECURECORE_REQUIRE_TSAN=1 scripts/run-sanitizers.sh
```

Collect a concise diagnostic report with:

```bash
scripts/diagnose-tsan.sh
```

A TSan startup failure is not evidence that the code is race-free or that a
race exists; no instrumented test has run yet.

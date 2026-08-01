# LeakSanitizer during libFuzzer smoke runs

The libFuzzer smoke script disables recoverable LeakSanitizer scans
inside the mutation loop:

- `ASAN_OPTIONS=detect_leaks=0`
- `-detect_leaks=0`

Allocation-heavy targets can otherwise spend most of a short fuzzing
budget repeatedly scanning the entire process after interesting inputs.
This can make a 10-second target appear to hang for tens of seconds while
executing very few inputs.

This does not remove leak testing from SecureCore. The complete
ASan/UBSan CTest suite still runs with `detect_leaks=1`, so ordinary test
paths remain leak-checked at process exit.

The smoke fuzzers continue to detect out-of-bounds access,
use-after-free, invalid frees, and undefined behavior.

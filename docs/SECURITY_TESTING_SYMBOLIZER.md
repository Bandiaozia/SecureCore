# libFuzzer `NEW_FUNC` symbolizer stalls

A smoke run may stop after a line such as:

```text
NEW_FUNC[1/1]:
```

while the same generated inputs complete quickly when replayed one at a
time. This indicates that the target is returning, but libFuzzer is
waiting while resolving the name of a newly covered function.

The smoke and diagnostic scripts therefore use:

```text
-print_funcs=0
-print_pcs=0
```

This only disables normal coverage-name printing. It does not disable
AddressSanitizer or UndefinedBehaviorSanitizer error detection.

When available, the scripts also set `ASAN_SYMBOLIZER_PATH` and
`LLVM_SYMBOLIZER_PATH` to an installed `llvm-symbolizer` executable so
actual sanitizer reports can still be symbolized.

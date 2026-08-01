#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FUZZER = PROJECT_ROOT / "build-fuzz/fuzzers/securecore-fuzz-proxy-headers"
CORPUS = PROJECT_ROOT / "build-fuzz/smoke-corpus/proxy"
FUZZ_LOG = PROJECT_ROOT / "fuzz-smoke.log"
OUTPUT = PROJECT_ROOT / "build-fuzz/proxy-fuzz-diagnostic"
REPORT = OUTPUT / "report.txt"
RESULT_ARCHIVE = PROJECT_ROOT / "proxy-fuzz-diagnostic-result.tar.gz"

PER_INPUT_TIMEOUT_SECONDS = 4.0
SLOW_INPUT_SECONDS = 1.0
MAX_COPIED_INPUTS = 12


def run_one(path: Path) -> tuple[str, float, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

    command = [
        str(FUZZER),
        str(path),
        "-runs=1",
        "-detect_leaks=0",
        "-timeout=2",
        "-max_len=4096",
        "-reduce_inputs=0",
        "-print_final_stats=1",
    ]

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=PER_INPUT_TIMEOUT_SECONDS,
            check=False,
        )
        elapsed = time.perf_counter() - started
        if completed.returncode == 0:
            status = "ok"
        else:
            status = f"exit={completed.returncode}"
        return status, elapsed, completed.stdout[-4000:]
    except subprocess.TimeoutExpired as error:
        elapsed = time.perf_counter() - started
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return "timeout", elapsed, output[-4000:]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_variant(source: Path, selector: int, destination: Path) -> None:
    data = source.read_bytes()
    if data:
        data = bytes([selector]) + data[1:]
    else:
        data = bytes([selector])
    destination.write_bytes(data)


def create_structural_cases(destination: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    cases: dict[str, bytes] = {
        "forwarded-many-elements": bytes([0]) + (
            b"for=198.51.100.7," * 220
        )[:4095],
        "forwarded-many-parameters": bytes([0]) + (
            b"for=198.51.100.7;" + b"x=y;" * 500
        )[:4095],
        "xff-many-addresses": bytes([1]) + (
            b"198.51.100.7," * 300
        )[:4095],
        "x-real-ip-long": bytes([2]) + (
            b"1" * 4095
        ),
        "xfp-many-values": bytes([3]) + (
            b"https," * 680
        )[:4095],
        "quoted-backslashes": bytes([0]) + (
            b'for="' + b"\\" * 4000 + b'"'
        )[:4095],
    }

    paths: list[Path] = []
    for name, data in cases.items():
        path = destination / name
        path.write_bytes(data)
        paths.append(path)
    return paths


def main() -> int:
    if not FUZZER.is_file():
        print(f"Missing fuzzer: {FUZZER}")
        print("Run scripts/build-fuzzers.sh first.")
        return 2

    if not CORPUS.is_dir():
        print(f"Missing generated corpus: {CORPUS}")
        print("Run the proxy fuzz smoke test once before diagnostics.")
        return 2

    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir(parents=True)

    copied_dir = OUTPUT / "interesting-inputs"
    copied_dir.mkdir()
    variants_dir = OUTPUT / "selector-variants"
    variants_dir.mkdir()
    structural_dir = OUTPUT / "structural-cases"

    corpus_files = sorted(
        path for path in CORPUS.iterdir() if path.is_file()
    )

    lines: list[str] = []
    lines.append("SecureCore proxy fuzzer diagnostic")
    lines.append("=" * 40)
    lines.append(f"fuzzer={FUZZER}")
    lines.append(f"corpus={CORPUS}")
    lines.append(f"corpus_files={len(corpus_files)}")
    lines.append(
        f"per_input_timeout_seconds={PER_INPUT_TIMEOUT_SECONDS}"
    )
    lines.append(f"slow_threshold_seconds={SLOW_INPUT_SECONDS}")
    lines.append("")

    results: list[tuple[float, str, Path, str]] = []

    for index, path in enumerate(corpus_files, start=1):
        status, elapsed, output = run_one(path)
        results.append((elapsed, status, path, output))
        print(
            f"[{index}/{len(corpus_files)}] "
            f"{path.name} status={status} elapsed={elapsed:.3f}s"
        )

    results.sort(key=lambda item: item[0], reverse=True)

    lines.append("Slowest generated corpus inputs")
    lines.append("-" * 40)
    for elapsed, status, path, _ in results[:20]:
        lines.append(
            f"{elapsed:.3f}s status={status} "
            f"size={path.stat().st_size} "
            f"sha256={sha256(path)} file={path.name}"
        )
    lines.append("")

    interesting = [
        item for item in results
        if item[1] != "ok" or item[0] >= SLOW_INPUT_SECONDS
    ]

    lines.append(f"interesting_inputs={len(interesting)}")
    for elapsed, status, path, output in interesting[:MAX_COPIED_INPUTS]:
        copied = copied_dir / path.name
        shutil.copy2(path, copied)
        lines.append(
            f"copied {path.name}: status={status} elapsed={elapsed:.3f}s"
        )
        if status != "ok":
            output_path = copied_dir / f"{path.name}.output.txt"
            output_path.write_text(output, encoding="utf-8", errors="replace")
    lines.append("")

    if results:
        slowest = results[0][2]
        lines.append(
            f"selector_variants_source={slowest.name} "
            f"sha256={sha256(slowest)}"
        )
        selector_names = {
            0: "Forwarded",
            1: "X-Forwarded-For",
            2: "X-Real-IP",
            3: "X-Forwarded-Proto",
        }
        for selector, name in selector_names.items():
            variant = variants_dir / f"selector-{selector}"
            create_variant(slowest, selector, variant)
            status, elapsed, output = run_one(variant)
            lines.append(
                f"selector={selector} header={name} "
                f"status={status} elapsed={elapsed:.3f}s "
                f"size={variant.stat().st_size}"
            )
            if status != "ok":
                (variants_dir / f"selector-{selector}.output.txt").write_text(
                    output,
                    encoding="utf-8",
                    errors="replace",
                )
        lines.append("")

    lines.append("Deterministic structural cases")
    lines.append("-" * 40)
    for case in create_structural_cases(structural_dir):
        status, elapsed, output = run_one(case)
        lines.append(
            f"{case.name}: status={status} elapsed={elapsed:.3f}s "
            f"size={case.stat().st_size}"
        )
        if status != "ok":
            (structural_dir / f"{case.name}.output.txt").write_text(
                output,
                encoding="utf-8",
                errors="replace",
            )
    lines.append("")

    if FUZZ_LOG.is_file():
        log_lines = FUZZ_LOG.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        lines.append("Tail of fuzz-smoke.log")
        lines.append("-" * 40)
        lines.extend(log_lines[-100:])
        lines.append("")

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if RESULT_ARCHIVE.exists():
        RESULT_ARCHIVE.unlink()
    with tarfile.open(RESULT_ARCHIVE, "w:gz") as archive:
        archive.add(OUTPUT, arcname=OUTPUT.name)

    print()
    print(f"Report: {REPORT}")
    print(f"Archive: {RESULT_ARCHIVE}")
    print("Upload proxy-fuzz-diagnostic-result.tar.gz.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

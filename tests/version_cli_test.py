#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess
import sys


VERSION_PATTERN = re.compile(
    r"^secure-(?:server|admin) "
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)? "
    r"\([0-9A-Za-z._-]+\)$"
)


def check(binary: str) -> None:
    completed = subprocess.run(
        [binary, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"{binary} --version exited with {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )

    output = completed.stdout.strip()
    if not VERSION_PATTERN.fullmatch(output):
        raise RuntimeError(
            f"Unexpected version output from {binary}: {output!r}"
        )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: version_cli_test.py <secure-server> <secure-admin>"
        )

    check(sys.argv[1])
    check(sys.argv[2])

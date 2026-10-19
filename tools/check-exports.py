#!/usr/bin/env python3
"""Verify the shared library's exported ABI and C++ header compatibility."""

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    library, expected_file, include = sys.argv[1:]
    output = subprocess.check_output(["nm", "-D", "--defined-only", library], text=True)
    observed = sorted(line.split()[-1] for line in output.splitlines() if line.split())
    expected = sorted(Path(expected_file).read_text().splitlines())
    if observed != expected:
        raise SystemExit(f"ABI exports differ: expected {expected!r}, got {observed!r}")
    subprocess.run(
        [
            os.environ.get("CXX", "c++"),
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-x",
            "c++",
            "-I",
            include,
            "-",
        ],
        input="#include <peios/netd.h>\n",
        text=True,
        check=True,
    )


if __name__ == "__main__":
    main()

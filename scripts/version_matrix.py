"""Prove the supported version range: run the full test suite on every Python / library combination.

SniffDash declares only minimum versions (``requires-python = ">=3.11"``, ``pandas>=2.2`` …).
This script checks that claim instead of assuming it. Each *cell* is an isolated
environment built by uv:

* ``lowest``  — every direct dependency at its declared minimum (uv ``--resolution lowest-direct``),
  on the oldest supported Python. If a minimum is too low, this cell fails.
* ``highest`` — the newest release of every dependency, on each supported Python.

Old library minimums often have no builds for brand-new Python versions, so "oldest
Python + oldest libraries" and "every Python + newest libraries" together cover the range.

Run it before every push (the GitHub workflow runs the same script per cell)::

    python scripts/version_matrix.py                      # every cell
    python scripts/version_matrix.py --python 3.12 --resolution highest
    python scripts/version_matrix.py --clean              # delete the .matrix/ environments

Where files go: Python interpreters and package downloads → uv's cache
(Windows: %LOCALAPPDATA%\\uv); environments → ``.matrix/`` in the repo (git-ignored).
Nothing is installed system-wide. Requires uv: ``pip install uv``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_DIR = ROOT / ".matrix"
REQUIREMENTS = ROOT / "requirements.txt"

OLDEST_PYTHON = "3.11"
PYTHONS = ["3.11", "3.12", "3.13", "3.14"]
RESOLUTIONS = {"lowest": "lowest-direct", "highest": "highest"}
CELLS = [(OLDEST_PYTHON, "lowest")] + [(python, "highest") for python in PYTHONS]


def find_uv() -> str:
    try:
        import uv
        return uv.find_uv_bin()
    except ImportError:
        found = shutil.which("uv")
        if not found:
            sys.exit("uv is not installed. Install it with:  pip install uv")
        return found


def run_cell(uv: str, python: str, resolution: str) -> tuple[bool, str, Path]:
    """Build the cell's environment and run pytest in it. Returns (passed, summary line, log path)."""
    name = f"py{python}-{resolution}"
    env_dir = MATRIX_DIR / name
    log = MATRIX_DIR / f"{name}.log"
    env_python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    steps = [
        [uv, "venv", "--quiet", "--clear", "--python", python, str(env_dir)],
        [uv, "pip", "install", "--quiet", "--python", str(env_python),
         "--resolution", RESOLUTIONS[resolution], "-r", str(REQUIREMENTS)],
        [str(env_python), "-m", "pytest", "-q", "-p", "no:cacheprovider"],
    ]
    with log.open("w", encoding="utf-8") as out:
        for step in steps:
            out.write(f"$ {' '.join(step)}\n")
            out.flush()
            result = subprocess.run(step, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
            if result.returncode != 0:
                break
    lines = [line.strip() for line in log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    summary = lines[-1] if lines else "(no output)"
    return result.returncode == 0, summary, log


def installed_versions(env_dir: Path, uv: str) -> str:
    env_python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    out = subprocess.run([uv, "pip", "freeze", "--python", str(env_python)], capture_output=True, text=True)
    wanted = {"pandas", "numpy", "streamlit", "plotly", "google-genai", "scapy", "pyshark", "python-dotenv", "pytest"}
    return ", ".join(line for line in out.stdout.splitlines() if line.split("==")[0].lower() in wanted)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--python", choices=PYTHONS, help="run only cells with this Python version")
    parser.add_argument("--resolution", choices=list(RESOLUTIONS), help="run only cells with this resolution")
    parser.add_argument("--clean", action="store_true", help="delete the .matrix/ environments and exit")
    args = parser.parse_args()

    if args.clean:
        shutil.rmtree(MATRIX_DIR, ignore_errors=True)
        print(f"Deleted {MATRIX_DIR}")
        return 0

    cells = [(p, r) for p, r in CELLS
             if (args.python is None or p == args.python) and (args.resolution is None or r == args.resolution)]
    if not cells:  # e.g. --python 3.12 --resolution lowest: not a cell (see the module docstring)
        print("No matrix cell matches those options.", file=sys.stderr)
        return 2

    uv = find_uv()
    MATRIX_DIR.mkdir(exist_ok=True)
    results = []
    for python, resolution in cells:
        print(f"→ Python {python}, {resolution} dependencies …", flush=True)
        start = time.perf_counter()
        passed, summary, log = run_cell(uv, python, resolution)
        elapsed = time.perf_counter() - start
        versions = installed_versions(MATRIX_DIR / f"py{python}-{resolution}", uv)
        results.append((python, resolution, passed, summary, log))
        print(f"  {'PASS' if passed else 'FAIL'} in {elapsed:.0f} s: {summary}")
        print(f"  {versions}", flush=True)
        if not passed:
            print(f"  full log: {log}")

    print("\nPython  Dependencies  Result")
    for python, resolution, passed, summary, _ in results:
        print(f"{python:<7} {resolution:<13} {'PASS' if passed else 'FAIL'}  {summary}")
    return 0 if all(passed for _, _, passed, _, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())

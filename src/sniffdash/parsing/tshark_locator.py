"""Find the tshark executable (needed by PyShark).

The Wireshark installer on Windows does not add tshark to PATH, so we also
probe the standard install locations. ``TSHARK_PATH`` (env / .env) overrides all.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _candidates() -> list[Path]:
    paths: list[Path] = []
    for env_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env_var)
        if base:
            paths.append(Path(base) / "Wireshark" / "tshark.exe")
    paths += [
        Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
        Path("/usr/bin/tshark"),
        Path("/usr/local/bin/tshark"),
        Path("/opt/homebrew/bin/tshark"),
    ]
    return paths


def find_tshark() -> str | None:
    """Return the path to tshark, or None if it is not installed."""
    override = os.environ.get("TSHARK_PATH")
    if override:
        return override if Path(override).is_file() else None
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    return next((str(p) for p in _candidates() if p.is_file()), None)

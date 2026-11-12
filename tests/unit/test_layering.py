"""Architecture guard (AC9): only the presentation layer may import Streamlit or Plotly.

Checked on the source files themselves, so a stray `import streamlit` in the core
fails the build instead of quietly coupling business logic to the UI framework.
"""

from __future__ import annotations

import re
from pathlib import Path

import sniffdash

ROOT = Path(sniffdash.__file__).parent
UI_IMPORT = re.compile(r"^\s*(?:import|from)\s+(streamlit|plotly)\b", re.MULTILINE)


def test_only_the_ui_package_imports_streamlit_or_plotly():
    offenders = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
                       if UI_IMPORT.search(p.read_text(encoding="utf-8"))
                       and p.relative_to(ROOT).parts[0] != "ui")
    assert offenders == []


def test_core_layers_do_not_import_the_ui():
    core = [p for p in ROOT.rglob("*.py") if p.relative_to(ROOT).parts[0] != "ui"]
    assert not [str(p) for p in core if "sniffdash.ui" in p.read_text(encoding="utf-8")]

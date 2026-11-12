"""New-user setup guarantees (AC10): one dependency list, and a working demo command."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from sniffdash.demo import main as demo_main
from sniffdash.parsing.scapy_parser import ScapyParser

ROOT = Path(__file__).resolve().parents[2]


def _names(specs) -> dict[str, str]:
    out = {}
    for spec in specs:
        name = re.split(r"[<>=!~\[ ]", spec.strip(), maxsplit=1)[0].lower()
        out[name] = spec.strip()
    return out


def test_requirements_txt_matches_pyproject():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    expected = _names(project["dependencies"] + project["optional-dependencies"]["dev"])
    lines = [l for l in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.lstrip().startswith("#")]
    assert _names(lines) == expected    # same packages AND the same version constraints


def test_demo_command_writes_parseable_captures(tmp_path, capsys):
    assert demo_main([str(tmp_path / "captures")]) == 0
    files = sorted((tmp_path / "captures").glob("*.pcap"))
    assert [f.name for f in files] == ["demo_http.pcap", "demo_https.pcap"]
    assert ScapyParser().parse(files[0]).packet_count == 13
    assert "streamlit run app.py" in capsys.readouterr().out

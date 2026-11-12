"""Shared pytest fixtures.

Test captures are GENERATED with Scapy at test time instead of being committed:
* the repo stays small and contains no real (possibly private) traffic;
* every expected value is known exactly, because we wrote the packets.

The capture builders live in ``sniffdash.demo`` (shared with the dashboard's demo
data); see its docstring for the 13-frame reference scenario's frame table.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sniffdash.demo import (  # noqa: F401  (re-exported for test modules)
    CLIENT, RESOLVER, SERVER, T0, build_edge_cases, build_http_scenario, build_https_flows,
    build_pipelined, build_port_reuse, build_retransmission, build_two_in_one_segment, write_pcap,
)


def pytest_collection_modifyitems(config, items):
    """Live Gemini tests spend free-tier quota: run them ONLY when explicitly selected
    with ``-m live_llm``, never as part of an ordinary ``pytest`` run."""
    if "live_llm" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="live Gemini test: run with  pytest -m live_llm")
    for item in items:
        if "live_llm" in item.keywords:
            item.add_marker(skip)


# --- File fixtures (session-scoped: generated once per test run) ----------------------

@pytest.fixture(scope="session")
def capture_dir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("captures")


@pytest.fixture(scope="session")
def http_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "http_scenario.pcap", build_http_scenario())


@pytest.fixture(scope="session")
def http_pcapng(capture_dir) -> Path:
    from scapy.utils import wrpcapng
    path = capture_dir / "http_scenario.pcapng"
    wrpcapng(str(path), build_http_scenario())
    return path


@pytest.fixture(scope="session")
def edge_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "edge_cases.pcap", build_edge_cases())


@pytest.fixture(scope="session")
def https_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "https_flows.pcap", build_https_flows())


@pytest.fixture(scope="session")
def pipelined_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "pipelined.pcap", build_pipelined())


@pytest.fixture(scope="session")
def port_reuse_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "port_reuse.pcap", build_port_reuse())


@pytest.fixture(scope="session")
def retransmission_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "retransmission.pcap", build_retransmission())


@pytest.fixture(scope="session")
def two_in_one_pcap(capture_dir) -> Path:
    return write_pcap(capture_dir / "two_in_one_segment.pcap", build_two_in_one_segment())


@pytest.fixture(scope="session")
def truncated_pcap(capture_dir, http_pcap) -> Path:
    """The reference capture with the last 10 bytes chopped off (packet 13 is cut short)."""
    path = capture_dir / "truncated.pcap"
    path.write_bytes(http_pcap.read_bytes()[:-10])
    return path


@pytest.fixture(scope="session")
def header_only_pcap(capture_dir) -> Path:
    """A valid pcap global header with zero packets."""
    path = capture_dir / "empty_capture.pcap"
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return path


@pytest.fixture(scope="session")
def garbage_file(capture_dir) -> Path:
    path = capture_dir / "not_a_capture.pcap"
    path.write_bytes(b"This is a text file pretending to be a pcap.\n" * 10)
    return path


@pytest.fixture(scope="session")
def empty_file(capture_dir) -> Path:
    path = capture_dir / "zero_bytes.pcap"
    path.write_bytes(b"")
    return path


# --- Backend availability -------------------------------------------------------------

def tshark_available() -> bool:
    from sniffdash.parsing.pyshark_parser import PySharkParser
    return PySharkParser.is_available()


requires_tshark = pytest.mark.skipif(not tshark_available(), reason="tshark (Wireshark) not installed")


def backend_params():
    """Parametrize a fixture over both parsers; PyShark auto-skips without tshark."""
    from sniffdash.parsing.pyshark_parser import PySharkParser
    from sniffdash.parsing.scapy_parser import ScapyParser
    return [
        pytest.param(PySharkParser, marks=[requires_tshark, pytest.mark.tshark], id="pyshark"),
        pytest.param(ScapyParser, id="scapy"),
    ]


# --- LLM test doubles (defined in llm_doubles.py; re-exported for existing imports) ---

from llm_doubles import ScriptedClient, call, last_tool_result  # noqa: E402,F401


def analyze_file(parser_cls, path: Path):
    """Parse + analyze a capture end-to-end; returns (report, repository)."""
    from sniffdash.analysis import AnalysisEngine
    from sniffdash.repository import InMemoryFrameRepository
    outcome = parser_cls().parse(path)
    repo = InMemoryFrameRepository.from_outcome(outcome)
    return AnalysisEngine().run(repo, source=outcome.source, issues=outcome.issues), repo

"""Integration tests for features that ONLY tshark provides, plus backend parity.

* tshark's request↔response links (``request_in`` / ``response_in`` / ``time``).
  Step 2's pairing strategy will trust these first.
* Cross-backend parity: Scapy and PyShark must agree on everything the analysis
  layer depends on. If this test fails, the fallback backend would silently produce
  different statistics, so it guards the Liskov Substitution Principle.
"""

from __future__ import annotations

import pytest

from conftest import requires_tshark
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.factory import ParserFactory
from sniffdash.parsing.pyshark_parser import PySharkParser
from sniffdash.parsing.scapy_parser import ScapyParser

pytestmark = [requires_tshark, pytest.mark.tshark]


@pytest.fixture(scope="module")
def pyshark_frames(http_pcap):
    return {f.number: f for f in PySharkParser().parse(http_pcap).frames}


def test_tshark_pairing_hints(pyshark_frames):
    assert pyshark_frames[4].layer("http")["response_in"] == 5
    assert pyshark_frames[5].layer("http")["request_in"] == 4
    assert pyshark_frames[5].layer("http")["time"] == pytest.approx(0.120, abs=1e-6)
    assert pyshark_frames[13].layer("http")["response_in"] is None  # unanswered POST


def test_tcp_flags_and_payload_length(pyshark_frames):
    assert pyshark_frames[1].layer("tcp")["flags"] == "S"
    assert pyshark_frames[2].layer("tcp")["flags"] == "SA"
    assert pyshark_frames[4].layer("tcp")["payload_len"] > 0


def test_auto_factory_prefers_pyshark(http_pcap):
    assert ParserFactory.default().create(http_pcap).backend is Backend.PYSHARK


def test_backends_agree_on_everything_analysis_needs(http_pcap):
    def essence(frame):
        http = frame.layer("http") or {}
        return (frame.number, round(frame.timestamp, 6), frame.length, frame.src, frame.dst,
                frame.transport, frame.stream_id, frame.highest_protocol,
                http.get("kind"), http.get("method"), http.get("status_code"),
                # tshark also annotates RESPONSES with their request's URI; Scapy
                # cannot. Analysis takes the URI from the request, so compare only that.
                http.get("uri") if http.get("kind") == "request" else None)

    py = [essence(f) for f in PySharkParser().parse(http_pcap).frames]
    sc = [essence(f) for f in ScapyParser().parse(http_pcap).frames]
    assert py == sc

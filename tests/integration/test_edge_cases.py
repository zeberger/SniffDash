"""Integration tests for paths the reference scenario never reaches (audit findings R2, R3).

* TLS extraction: the PyShark TLS extractor existed but was never executed by a test.
* Malformed packets from REAL backends: AC4 was proven only with a fake backend.
See ``build_edge_cases`` in ``tests/conftest.py`` for the 2-frame capture.
"""

from __future__ import annotations

import pytest

from conftest import requires_tshark
from sniffdash.domain.errors import IssueSeverity
from sniffdash.parsing.pyshark_parser import PySharkParser
from sniffdash.parsing.scapy_parser import ScapyParser


@pytest.fixture(params=[
    pytest.param(PySharkParser, marks=[requires_tshark, pytest.mark.tshark], id="pyshark"),
    pytest.param(ScapyParser, id="scapy"),
])
def edge_outcome(request, edge_pcap):
    return request.param().parse(edge_pcap)


@requires_tshark
@pytest.mark.tshark
def test_pyshark_extracts_tls_client_hello(edge_pcap):
    frame = PySharkParser().parse(edge_pcap).frames[0]
    tls = frame.layer("tls")
    assert frame.highest_protocol == "tls"
    assert tls["sni"] == "secure.example.com"            # the server name, visible before encryption
    assert (tls["content_type"], tls["handshake_type"]) == (22, 1)  # handshake / ClientHello


def test_scapy_degrades_tls_to_plain_tcp(edge_pcap):
    # Documented fallback limitation: without a TLS dissector the frame is still
    # parsed correctly at the TCP level; it is not lost or mislabelled.
    frame = ScapyParser().parse(edge_pcap).frames[0]
    assert frame.layer("tls") is None
    assert frame.highest_protocol == "tcp" and frame.dst.port == 443


def test_malformed_packet_is_kept_and_reported(edge_outcome):
    # AC4 against real dissectors: frame 2 survives, and a WARNING names it.
    assert [f.number for f in edge_outcome.frames] == [1, 2]
    assert edge_outcome.frames[1].has_protocol("dns")
    warnings = [i for i in edge_outcome.issues if i.severity is IssueSeverity.WARNING]
    assert [i.frame_number for i in warnings] == [2]
    assert not edge_outcome.partial  # one bad packet does not make the capture partial

"""Integration: stream-bound edge cases found in the Phase 2 review (AC11–AC13).

Each capture reproduces a probe-verified way pairing could go wrong in dense
traffic. The tests assert the end-to-end result on BOTH parsers.
"""

from __future__ import annotations

import pytest

from conftest import analyze_file, backend_params, requires_tshark
from sniffdash.domain.errors import IssueSeverity
from sniffdash.domain.results import HttpAnalysisResult
from sniffdash.parsing.pyshark_parser import PySharkParser
from sniffdash.parsing.scapy_parser import ScapyParser


@pytest.fixture(params=backend_params())
def parser_cls(request):
    return request.param


def pairs(parser_cls, path):
    report, repo = analyze_file(parser_cls, path)
    http = report.get(HttpAnalysisResult)
    return [(t.request.uri, t.status_code) for t in http.transactions], report, repo


def test_port_reuse_never_pairs_across_connections(parser_cls, port_reuse_pcap):
    # AC11: /lost (old connection, never answered) must NOT steal /second's 200.
    rows, _, repo = pairs(parser_cls, port_reuse_pcap)
    assert rows == [("/lost", None), ("/second", 200)]
    assert (repo.get(4).stream_id, repo.get(10).stream_id) == (0, 1)  # two streams, like tshark


def test_port_reuse_stream_ids_match_across_backends(port_reuse_pcap):
    if not PySharkParser.is_available():
        pytest.skip("tshark not installed")
    ids = lambda cls: [f.stream_id for f in cls().parse(port_reuse_pcap).frames]  # noqa: E731
    assert ids(PySharkParser) == ids(ScapyParser)


def test_retransmission_creates_no_ghost_request(parser_cls, retransmission_pcap):
    # AC12: exactly one transaction; the duplicate segment is not a second request.
    rows, report, _ = pairs(parser_cls, retransmission_pcap)
    assert rows == [("/retx", 200)]


def test_scapy_retransmission_is_reported(retransmission_pcap):
    _, report, _ = pairs(ScapyParser, retransmission_pcap)
    info = [i for i in report.issues if i.severity is IssueSeverity.INFO]
    assert [(i.frame_number, i.message) for i in info] == [(5, "Retransmitted HTTP message ignored.")]


@requires_tshark
@pytest.mark.tshark
def test_pyshark_pairs_two_responses_in_one_segment(two_in_one_pcap):
    # AC13: both messages in frame 6 are extracted and paired in order.
    rows, report, _ = pairs(PySharkParser, two_in_one_pcap)
    assert rows == [("/a", 200), ("/b", 404)]
    assert [t.response.frame_number for t in report.get(HttpAnalysisResult).transactions] == [6, 6]


def test_scapy_two_responses_in_one_segment_is_a_documented_limitation(two_in_one_pcap):
    # Scapy decodes only the first message in a segment, so /b stays unanswered.
    # Asserted explicitly so a future Scapy change is noticed rather than silent.
    rows, _, _ = pairs(ScapyParser, two_in_one_pcap)
    assert rows == [("/a", 200), ("/b", None)]

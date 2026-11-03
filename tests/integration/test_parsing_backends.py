"""Integration tests: real backends parsing the generated reference captures.

Each behavior is tested against BOTH backends through one parametrized fixture,
so every test doubles as a Liskov-substitution check. PyShark cases are skipped
automatically when tshark is not installed (e.g. on a grader's machine).
See ``tests/conftest.py`` for the 13-frame reference scenario.
"""

from __future__ import annotations

import pickle

import pytest

from conftest import CLIENT, RESOLVER, SERVER, T0, requires_tshark
from sniffdash.domain.errors import CorruptCaptureError, IssueSeverity, UnsupportedFormatError
from sniffdash.domain.models import Transport
from sniffdash.parsing.pyshark_parser import PySharkParser
from sniffdash.parsing.scapy_parser import ScapyParser
from sniffdash.repository import InMemoryFrameRepository


@pytest.fixture(params=[
    pytest.param(PySharkParser, marks=[requires_tshark, pytest.mark.tshark], id="pyshark"),
    pytest.param(ScapyParser, id="scapy"),
])
def parser(request):
    return request.param()


@pytest.fixture
def outcome(parser, http_pcap):
    return parser.parse(http_pcap)


@pytest.fixture
def frames(outcome):
    return {f.number: f for f in outcome.frames}


# --- Frame-level facts -------------------------------------------------------------

def test_all_frames_parsed_with_wireshark_numbering(outcome):
    assert [f.number for f in outcome.frames] == list(range(1, 14))
    assert not outcome.partial and not outcome.has_errors


def test_timestamps_are_exact(frames):
    # 0.120 s request→response gap must survive parsing precisely (Req. 28 relies on it).
    assert frames[1].timestamp == pytest.approx(T0, abs=1e-6)
    assert frames[5].timestamp - frames[4].timestamp == pytest.approx(0.120, abs=1e-6)


def test_endpoints_and_streams(frames):
    assert str(frames[4].src) == f"{CLIENT}:50000" and str(frames[4].dst) == f"{SERVER}:80"
    assert (frames[1].transport, frames[1].stream_id) == (Transport.TCP, 0)
    assert frames[13].stream_id == 1                    # second TCP connection
    assert (frames[8].transport, frames[8].stream_id) == (Transport.UDP, 0)


def test_highest_protocol_classification(frames):
    assert frames[1].highest_protocol == "tcp"        # bare SYN
    assert frames[4].highest_protocol == "http"       # request
    assert frames[5].highest_protocol == "http"       # response (NOT "data-text-lines")
    assert frames[8].highest_protocol == "dns"


# --- HTTP extraction ---------------------------------------------------------------

def test_http_request_fields(frames):
    http = frames[4].layer("http")
    assert (http["kind"], http["method"], http["uri"], http["host"]) == \
        ("request", "GET", "/index.html", "example.com")
    assert ("User-Agent", "sniffdash-test") in http["headers"]


def test_http_response_fields(frames):
    ok, missing = frames[5].layer("http"), frames[7].layer("http")
    assert (ok["kind"], ok["status_code"], ok["reason"]) == ("response", 200, "OK")
    assert "<html>hello</html>" in ok["body"]
    assert missing["status_code"] == 404 and missing["reason"] == "Not Found"


def test_unanswered_post_is_still_extracted(frames):
    http = frames[13].layer("http")
    assert (http["method"], http["host"]) == ("POST", "api.example.com")
    assert '"alice"' in http["body"]


def test_non_http_frames_have_no_http_layer(frames):
    assert frames[1].layer("http") is None and frames[8].layer("http") is None


# --- DNS extraction ----------------------------------------------------------------

def test_dns_fields(frames):
    query, answer = frames[8].layer("dns"), frames[9].layer("dns")
    assert (query["id"], query["is_response"], query["qname"]) == (0x1234, False, "example.com")
    # Lists become tuples inside a Frame (deep immutability).
    assert answer["is_response"] and answer["answers"] == (SERVER,) and answer["rcode"] == 0
    assert str(frames[9].src) == f"{RESOLVER}:53"


# --- Robustness --------------------------------------------------------------------

def test_pcapng_gives_identical_frames(parser, http_pcap, http_pcapng):
    a, b = parser.parse(http_pcap), parser.parse(http_pcapng)
    assert [(f.number, f.src, f.dst, f.highest_protocol) for f in a.frames] == \
           [(f.number, f.src, f.dst, f.highest_protocol) for f in b.frames]


def test_truncated_capture_is_partial_not_fatal(parser, truncated_pcap):
    outcome = parser.parse(truncated_pcap)
    assert outcome.partial and outcome.has_errors
    assert any("truncated" in i.message for i in outcome.issues if i.severity is IssueSeverity.ERROR)
    assert [f.number for f in outcome.frames][:12] == list(range(1, 13))  # first 12 intact


def test_garbage_and_empty_files_raise_typed_errors(parser, garbage_file, empty_file):
    with pytest.raises(UnsupportedFormatError):
        parser.parse(garbage_file)
    with pytest.raises(CorruptCaptureError):
        parser.parse(empty_file)


def test_zero_packet_capture(parser, header_only_pcap):
    outcome = parser.parse(header_only_pcap)
    assert outcome.frames == () and not outcome.partial


# --- Into the repository -----------------------------------------------------------

def test_outcome_flows_into_repository(outcome):
    repo = InMemoryFrameRepository.from_outcome(outcome)
    assert [f.number for f in repo.by_stream(Transport.TCP, 0)] == [1, 2, 3, 4, 5, 6, 7]
    assert [f.number for f in repo.iter("http")] == [4, 5, 6, 7, 13]
    df = repo.to_dataframe()
    assert len(df) == 13 and df["length"].sum() == sum(f.length for f in outcome.frames)


def test_outcome_is_picklable_for_streamlit_cache(outcome):
    assert pickle.loads(pickle.dumps(outcome)) == outcome

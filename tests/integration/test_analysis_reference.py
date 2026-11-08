"""Integration: parse → repository → AnalysisEngine on the reference and pipelined captures.

Every expected value comes from the scenario table in ``tests/conftest.py``, so these
tests check the WHOLE pipeline against known ground truth, on both parsers.
"""

from __future__ import annotations

import pickle

import pytest

from conftest import CLIENT, SERVER, T0, analyze_file, backend_params
from sniffdash.analysis.analyzers.http import HttpStreamReconstructor
from sniffdash.domain.results import HttpAnalysisResult, TrafficTimeline


@pytest.fixture(params=backend_params())
def parser_cls(request):
    return request.param


@pytest.fixture
def analyzed(parser_cls, http_pcap):
    return analyze_file(parser_cls, http_pcap)


@pytest.fixture
def http(analyzed):
    return analyzed[0].get(HttpAnalysisResult)


# --- Summary & timeline (AC1, AC2) ------------------------------------------------

def test_summary(analyzed):
    s = analyzed[0].summary
    assert s.packet_count == 13
    assert s.start_ts == pytest.approx(T0) and s.duration_s == pytest.approx(0.5)
    assert s.top_sources[0] == (CLIENT, 8)                 # 8 of 13 frames come from the client
    assert sum(c for _, c in s.protocol_distribution) == 13
    assert dict(s.protocol_distribution)["http"] == 5      # 4, 5, 6, 7, 13


def test_timeline(analyzed):
    report, repo = analyzed
    t = report.get(TrafficTimeline)
    assert t.bucket_seconds == 0.01
    assert sum(p for _, p, _ in t.buckets) == 13
    assert sum(b for _, _, b in t.buckets) == report.summary.total_bytes


# --- HTTP transactions (AC3, AC5) -----------------------------------------------------

def test_exactly_the_three_known_transactions(http):
    rows = [(t.id, t.request.method, t.request.uri, t.status_code,
             t.request.frame_number, t.response.frame_number if t.response else None)
            for t in http.transactions]
    assert rows == [
        ("tx-4", "GET", "/index.html", 200, 4, 5),
        ("tx-6", "GET", "/missing", 404, 6, 7),
        ("tx-13", "POST", "/api/login", None, 13, None),
    ]
    assert http.orphan_responses == ()


def test_response_times_and_endpoints(http):
    ok, missing, post = http.transactions
    assert ok.response_time_ms == pytest.approx(120.0, abs=1e-3)
    assert missing.response_time_ms == pytest.approx(60.0, abs=1e-3)
    assert post.response_time_ms is None
    assert (ok.request.src.ip, ok.request.dst.ip, ok.request.dst.port) == (CLIENT, SERVER, 80)
    assert ok.request.effective_host == "example.com" and post.request.effective_host == "api.example.com"


def test_pipelined_capture_pairs_in_request_order(parser_cls, pipelined_pcap):
    # AC4: tshark's own links mispair this capture; our FIFO must not.
    http = analyze_file(parser_cls, pipelined_pcap)[0].get(HttpAnalysisResult)
    assert [(t.request.uri, t.status_code) for t in http.transactions] == [("/a", 200), ("/b", 404)]


# --- Follow HTTP Stream (AC8) -----------------------------------------------------

def test_stream_view_of_answered_transaction(analyzed, http):
    _, repo = analyzed
    view = HttpStreamReconstructor().reconstruct(http.transactions[0], repo)
    assert view.request_text.startswith("GET /index.html HTTP/1.1\r\n")
    assert "Host: example.com" in view.request_text
    assert view.response_text.startswith("HTTP/1.1 200 OK") and "<html>hello</html>" in view.response_text
    assert view.frame_numbers == (4, 5)


def test_stream_view_of_unanswered_transaction(analyzed, http):
    _, repo = analyzed
    view = HttpStreamReconstructor().reconstruct(http.transactions[2], repo)
    assert view.response_text == "(no response captured)" and view.frame_numbers == (13,)
    assert '"alice"' in view.request_text


# --- Cache readiness (AC14) -------------------------------------------------------

def test_report_survives_pickle(analyzed):
    # st.cache_data stores results by pickling them: the round trip must be lossless.
    report = analyzed[0]
    assert pickle.loads(pickle.dumps(report)) == report


def test_analysis_is_deterministic(parser_cls, http_pcap):
    assert analyze_file(parser_cls, http_pcap)[0] == analyze_file(parser_cls, http_pcap)[0]

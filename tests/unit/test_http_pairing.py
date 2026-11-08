"""Unit tests for HTTP pairing: stream ID first, then FIFO within the stream.

Messages are hand-made, so every scenario (pipelining, interleaving, 100-Continue,
clock anomalies) is exact and independent of any parser.
"""

from __future__ import annotations

import pytest

from sniffdash.analysis.analyzers.http.messages import SequencedMessage
from sniffdash.analysis.analyzers.http.pairing import pair_by_stream
from sniffdash.domain.errors import IssueSeverity
from sniffdash.domain.models import Endpoint, HttpRequest, HttpResponse

CLIENT, SERVER = Endpoint("10.0.0.2", 50000), Endpoint("1.2.3.4", 80)
CLIENT2 = Endpoint("10.0.0.2", 50001)


def req(frame, ts, uri, stream=0, src=CLIENT, dst=SERVER, position=0):
    return SequencedMessage(HttpRequest(frame_number=frame, timestamp=ts, src=src, dst=dst,
                                        method="GET", uri=uri, stream_id=stream), frame, position)


def resp(frame, ts, code, stream=0, src=SERVER, dst=CLIENT, position=0):
    return SequencedMessage(HttpResponse(frame_number=frame, timestamp=ts, src=src, dst=dst,
                                         status_code=code, stream_id=stream), frame, position)


def summary(result):
    """(request uri, status or None) per transaction, in request-frame order."""
    return [(t.request.uri, t.status_code) for t in result.transactions]


def test_sequential():
    r = pair_by_stream([req(1, 1.0, "/a"), resp(2, 1.1, 200), req(3, 2.0, "/b"), resp(4, 2.2, 404)])
    assert summary(r) == [("/a", 200), ("/b", 404)]
    assert r.transactions[0].response_time_ms == pytest.approx(100.0)


def test_pipelined_requests_are_answered_in_order():
    # The case tshark's own links get wrong: both requests go out before any response.
    r = pair_by_stream([req(1, 1.0, "/a"), req(2, 1.01, "/b"), resp(3, 1.2, 200), resp(4, 1.3, 404)])
    assert summary(r) == [("/a", 200), ("/b", 404)]


def test_stream_id_takes_precedence_over_arrival_order():
    # Two connections interleaved: the FIRST response to arrive belongs to stream 1,
    # even though stream 0's request is older. FIFO is per stream, never global.
    r = pair_by_stream([
        req(1, 1.0, "/slow", stream=0),
        req(2, 1.1, "/fast", stream=1, src=CLIENT2),
        resp(3, 1.2, 200, stream=1, dst=CLIENT2),
        resp(4, 2.0, 500, stream=0),
    ])
    assert summary(r) == [("/slow", 500), ("/fast", 200)]


def test_response_must_travel_in_the_opposite_direction():
    wrong_way = resp(2, 1.1, 200, src=CLIENT, dst=SERVER)  # client→server "response"
    r = pair_by_stream([req(1, 1.0, "/a"), wrong_way])
    assert summary(r) == [("/a", None)] and len(r.orphans) == 1


def test_interim_100_continue_does_not_consume_the_request():
    r = pair_by_stream([req(1, 1.0, "/upload"), resp(2, 1.05, 100), resp(3, 1.5, 201)])
    assert summary(r) == [("/upload", 201)] and r.orphans == []


def test_101_switching_protocols_is_a_final_answer():
    assert summary(pair_by_stream([req(1, 1.0, "/ws"), resp(2, 1.1, 101)])) == [("/ws", 101)]


def test_orphan_response_without_request():
    r = pair_by_stream([resp(1, 1.0, 200), req(2, 2.0, "/a")])
    assert len(r.orphans) == 1 and summary(r) == [("/a", None)]


def test_response_before_request_is_reported_not_raised():
    r = pair_by_stream([req(5, 2.0, "/a"), resp(6, 1.0, 200)])  # clock went backwards
    assert summary(r) == [("/a", None)] and len(r.orphans) == 1
    issue, = r.issues
    assert issue.severity is IssueSeverity.WARNING and issue.frame_number == 6


def test_two_requests_in_one_frame_get_distinct_ids():
    r = pair_by_stream([req(4, 1.0, "/a"), req(4, 1.0, "/b", position=1),
                        resp(5, 1.2, 200), resp(5, 1.2, 404, position=1)])
    assert [t.id for t in r.transactions] == ["tx-4", "tx-4.1"]
    assert summary(r) == [("/a", 200), ("/b", 404)]


def test_empty_input():
    r = pair_by_stream([])
    assert r.transactions == [] and r.orphans == [] and r.issues == []

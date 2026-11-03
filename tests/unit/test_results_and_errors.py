"""Unit tests for result containers and the error hierarchy."""

from __future__ import annotations

import pytest

from sniffdash.domain.errors import (
    CaptureError, CorruptCaptureError, FrameNotFoundError, IssueSeverity, LLMRateLimitError,
    ParseIssue, ParserUnavailableError, RepositoryError, SniffDashError, UnsupportedFormatError,
)
from sniffdash.domain.models import Endpoint, HttpRequest, HttpResponse, HttpTransaction
from sniffdash.domain.results import AnalysisReport, CaptureSummary, HttpAnalysisResult, ParseOutcome

A, B = Endpoint("1.1.1.1", 1234), Endpoint("2.2.2.2", 80)


def tx(req_frame: int, resp_frame: int | None) -> HttpTransaction:
    req = HttpRequest(frame_number=req_frame, timestamp=float(req_frame), src=A, dst=B, method="GET", uri="/")
    resp = None if resp_frame is None else HttpResponse(
        frame_number=resp_frame, timestamp=float(resp_frame), src=B, dst=A, status_code=200)
    return HttpTransaction(f"tx{req_frame}", req, resp)


class TestErrorHierarchy:
    @pytest.mark.parametrize("exc", [UnsupportedFormatError, CorruptCaptureError, ParserUnavailableError])
    def test_capture_errors_share_a_base(self, exc):
        # The UI can catch CaptureError once for every file problem.
        assert issubclass(exc, CaptureError) and issubclass(exc, SniffDashError)

    def test_frame_not_found_is_also_a_key_error(self):
        assert issubclass(FrameNotFoundError, RepositoryError)
        assert issubclass(FrameNotFoundError, KeyError)

    def test_llm_errors_are_sniffdash_errors(self):
        assert issubclass(LLMRateLimitError, SniffDashError)

    def test_parse_issue_str(self):
        assert str(ParseIssue("bad checksum", IssueSeverity.WARNING, 12)) == "[WARNING] frame 12: bad checksum"
        assert str(ParseIssue("cut short", IssueSeverity.ERROR)) == "[ERROR] capture: cut short"


class TestParseOutcome:
    def test_has_errors_only_for_error_severity(self):
        warn = ParseOutcome(frames=(), issues=(ParseIssue("w"),))
        err = ParseOutcome(frames=(), issues=(ParseIssue("e", IssueSeverity.ERROR),))
        assert not warn.has_errors
        assert err.has_errors


class TestCaptureSummary:
    def test_duration(self):
        s = CaptureSummary(packet_count=3, start_ts=10.0, end_ts=12.5)
        assert s.duration_s == 2.5
        assert s.start.year == 1970

    def test_empty_capture_duration_is_zero(self):
        assert CaptureSummary().duration_s == 0.0
        assert CaptureSummary().start is None


class TestHttpAnalysisResult:
    def test_unanswered_and_lookup_by_either_frame(self):
        result = HttpAnalysisResult(transactions=(tx(4, 5), tx(6, None)))
        assert [t.id for t in result.unanswered] == ["tx6"]
        assert result.find_by_frame(5).id == "tx4"  # response frame finds its transaction
        assert result.find_by_frame(6).id == "tx6"
        assert result.find_by_frame(99) is None


class TestAnalysisReport:
    def test_typed_get(self):
        http = HttpAnalysisResult(transactions=(tx(1, 2),))
        report = AnalysisReport(source="x.pcap", summary=CaptureSummary(), results={"http": http})
        assert report.get(HttpAnalysisResult) is http
        assert report.get(CaptureSummary) is None  # not stored under results

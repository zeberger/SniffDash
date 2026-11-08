"""Unit tests for AnalysisEngine (fault isolation) and AnalyzerRegistry (Open/Closed)."""

from __future__ import annotations

import pytest

from sniffdash.analysis import AnalysisEngine, AnalyzerRegistry, analyzer_registry
from sniffdash.analysis.base import Analyzer
from sniffdash.domain.errors import AnalysisError, IssueSeverity, ParseIssue
from sniffdash.domain.models import Frame
from sniffdash.domain.results import AnalysisResult, CaptureSummary, HttpAnalysisResult, TrafficTimeline
from sniffdash.repository import InMemoryFrameRepository


class BoomResult(AnalysisResult):
    key = "boom"


class BoomAnalyzer(Analyzer):
    key = "boom"

    def analyze(self, repo, ctx):
        raise RuntimeError("kaboom")


class CountResult(AnalysisResult):
    key = "count"


class CountAnalyzer(Analyzer):
    key = "count"

    def analyze(self, repo, ctx):
        ctx.warn("counted", frame_number=1, severity=IssueSeverity.INFO)
        return CountResult()


@pytest.fixture
def repo():
    return InMemoryFrameRepository([Frame(number=1, timestamp=0.0, length=10)])


def test_failing_analyzer_is_isolated(repo):
    report = AnalysisEngine(analyzers=[BoomAnalyzer(), CountAnalyzer()]).run(repo)
    assert "count" in report.results and "boom" not in report.results  # others still ran
    error, = [i for i in report.issues if i.severity is IssueSeverity.ERROR]
    assert "Analyzer 'boom' failed: kaboom" in error.message


def test_failing_summary_raises(repo):
    with pytest.raises(AnalysisError, match="summary"):
        AnalysisEngine(summary=BoomAnalyzer(), analyzers=[]).run(repo)


def test_parse_issues_come_first_then_analysis_issues(repo):
    report = AnalysisEngine(analyzers=[CountAnalyzer()]).run(
        repo, source="x.pcap", issues=[ParseIssue("from parser")])
    assert [i.message for i in report.issues] == ["from parser", "counted"]
    assert report.source == "x.pcap" and isinstance(report.summary, CaptureSummary)


def test_builtin_analyzers_are_auto_discovered():
    keys = {cls.key for cls in analyzer_registry.registered()}
    assert {"http", "timeline"} <= keys and "summary" not in keys  # summary is mandatory, not a plugin


def test_default_engine_produces_typed_results(repo):
    report = AnalysisEngine().run(repo)
    assert report.get(TrafficTimeline) is not None and report.get(HttpAnalysisResult) is not None


def test_new_analyzer_registers_without_core_changes():
    registry = AnalyzerRegistry()  # isolated: no package discovery
    registry.register(CountAnalyzer)
    assert [a.key for a in registry.create_all()] == ["count"]


def test_duplicate_keys_are_rejected():
    registry = AnalyzerRegistry()
    registry.register(CountAnalyzer)

    class Impostor(Analyzer):
        key = "count"
        def analyze(self, repo, ctx): return CountResult()

    with pytest.raises(ValueError, match="Duplicate analyzer key"):
        registry.register(Impostor)

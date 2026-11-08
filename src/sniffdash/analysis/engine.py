"""AnalysisEngine: runs all analyzers over one repository and bundles an AnalysisReport.

Two rules mirror the parsing layer's robustness contract:

* The capture summary is **mandatory**: a report without one is meaningless, so
  its failure raises ``AnalysisError``.
* Every other analyzer is **isolated**: if one crashes, it becomes an ERROR issue,
  its result is omitted, and the remaining analyzers still run.

The engine is a pure function of its input (no hidden state, deterministic order),
which is what lets Phase 4 cache its output with ``st.cache_data``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from sniffdash.analysis.analyzers.summary import SummaryAnalyzer
from sniffdash.analysis.base import AnalysisContext, AnalysisOptions, Analyzer, analyzer_registry
from sniffdash.domain.errors import AnalysisError, IssueSeverity, ParseIssue
from sniffdash.domain.results import AnalysisReport, AnalysisResult, CaptureSummary
from sniffdash.repository.base import FrameRepository


class AnalysisEngine:
    def __init__(self, summary: Analyzer | None = None,
                 analyzers: Sequence[Analyzer] | None = None,
                 options: AnalysisOptions | None = None) -> None:
        # Dependency Injection: tests pass fakes; production uses the registry.
        self._summary = summary or SummaryAnalyzer()
        self._analyzers = list(analyzers) if analyzers is not None else analyzer_registry.create_all()
        self._options = options or AnalysisOptions()

    def run(self, repo: FrameRepository, *, source: str = "",
            issues: Iterable[ParseIssue] = ()) -> AnalysisReport:
        ctx = AnalysisContext(self._options)

        try:
            summary = self._summary.analyze(repo, ctx)
        except Exception as exc:
            raise AnalysisError(f"Capture summary could not be computed: {exc}") from exc
        if not isinstance(summary, CaptureSummary):
            raise AnalysisError(f"Summary analyzer returned {type(summary).__name__}, not CaptureSummary")

        results: dict[str, AnalysisResult] = {}
        for analyzer in self._analyzers:
            try:
                results[analyzer.key] = analyzer.analyze(repo, ctx)
            except Exception as exc:  # isolate: one analyzer must not sink the report
                ctx.warn(f"Analyzer '{analyzer.key}' failed: {exc}", severity=IssueSeverity.ERROR)

        return AnalysisReport(source=source, summary=summary, results=results,
                              issues=tuple(issues) + tuple(ctx.issues))

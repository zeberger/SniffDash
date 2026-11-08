"""HttpAnalyzer → HttpAnalysisResult (Reqs 27–28)."""

from __future__ import annotations

from sniffdash.analysis.analyzers.http.messages import build_messages
from sniffdash.analysis.analyzers.http.pairing import pair_by_stream
from sniffdash.analysis.base import AnalysisContext, Analyzer, register_analyzer
from sniffdash.domain.results import HttpAnalysisResult
from sniffdash.repository.base import FrameRepository


@register_analyzer
class HttpAnalyzer(Analyzer):
    key = HttpAnalysisResult.key

    def analyze(self, repo: FrameRepository, ctx: AnalysisContext) -> HttpAnalysisResult:
        pairing = pair_by_stream(build_messages(repo, ctx))
        ctx.issues.extend(pairing.issues)
        return HttpAnalysisResult(transactions=tuple(pairing.transactions),
                                  orphan_responses=tuple(pairing.orphans))

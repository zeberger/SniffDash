"""SummaryAnalyzer → CaptureSummary (Reqs 24–25).

Mandatory, so the engine runs it directly rather than through the registry (it is
deliberately NOT decorated with ``@register_analyzer``). Every metric is computed
from the repository's DataFrame view with vectorized Pandas operations.
"""

from __future__ import annotations

import pandas as pd

from sniffdash.analysis.base import AnalysisContext, Analyzer
from sniffdash.domain.results import CaptureSummary
from sniffdash.repository.base import FrameRepository


def ranked_counts(series: pd.Series, limit: int | None = None) -> tuple[tuple[str, int], ...]:
    """Value counts as ((value, count), ...): highest count first, ties by value.

    The tie-break makes output deterministic: two runs on the same capture must
    produce identical reports (required for caching and for stable tests).
    """
    counts = series.dropna().astype(str).value_counts()
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple((value, int(count)) for value, count in ranked[:limit])


class SummaryAnalyzer(Analyzer):
    key = CaptureSummary.key

    def analyze(self, repo: FrameRepository, ctx: AnalysisContext) -> CaptureSummary:
        df = repo.to_dataframe()
        if df.empty:
            return CaptureSummary()
        start, end = repo.time_range()
        top_n = ctx.options.top_n
        return CaptureSummary(
            packet_count=len(df),
            total_bytes=int(df["length"].sum()),
            start_ts=start,
            end_ts=end,
            top_sources=ranked_counts(df["src_ip"], top_n),
            top_destinations=ranked_counts(df["dst_ip"], top_n),
            # One bucket per frame (its highest protocol), so the slices sum to packet_count.
            protocol_distribution=ranked_counts(df["protocol"]),
        )

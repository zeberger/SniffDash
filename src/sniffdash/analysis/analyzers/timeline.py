"""TimelineAnalyzer → TrafficTimeline (Req. 26: traffic volume over time).

The bucket size adapts to the capture: the smallest "human" step on the ladder
below that keeps the series within ``max_timeline_buckets``. A 0.5 s capture gets
10 ms buckets; a one-hour capture gets 1 min buckets.
"""

from __future__ import annotations

import numpy as np

from sniffdash.analysis.base import AnalysisContext, Analyzer, register_analyzer
from sniffdash.domain.results import TrafficTimeline
from sniffdash.repository.base import FrameRepository

BUCKET_LADDER: tuple[float, ...] = (0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 600.0, 3600.0, 86400.0)

# Guards against float error putting a timestamp that lies exactly on a bucket
# boundary into the previous bucket (e.g. 0.5 / 0.01 = 49.999999…).
_EPSILON = 1e-9


def choose_bucket(duration: float, max_buckets: int) -> float:
    for step in BUCKET_LADDER:
        if int(duration / step + _EPSILON) + 1 <= max_buckets:
            return step
    return BUCKET_LADDER[-1]


@register_analyzer
class TimelineAnalyzer(Analyzer):
    key = TrafficTimeline.key

    def analyze(self, repo: FrameRepository, ctx: AnalysisContext) -> TrafficTimeline:
        df = repo.to_dataframe()
        if df.empty:
            return TrafficTimeline()
        start, end = repo.time_range()
        step = choose_bucket(end - start, ctx.options.max_timeline_buckets)
        n_buckets = int((end - start) / step + _EPSILON) + 1

        index = np.floor((df["timestamp"].to_numpy() - start) / step + _EPSILON).astype(int)
        packets = np.bincount(index, minlength=n_buckets)  # zero-filled: silences stay visible
        volume = np.bincount(index, weights=df["length"].to_numpy(), minlength=n_buckets)

        buckets = tuple((start + i * step, int(packets[i]), int(volume[i])) for i in range(n_buckets))
        return TrafficTimeline(bucket_seconds=step, buckets=buckets)

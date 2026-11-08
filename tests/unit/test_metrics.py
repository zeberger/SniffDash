"""Unit tests for SummaryAnalyzer and TimelineAnalyzer, using hand-made frames."""

from __future__ import annotations

import pandas as pd
import pytest

from sniffdash.analysis.analyzers.summary import SummaryAnalyzer, ranked_counts
from sniffdash.analysis.analyzers.timeline import TimelineAnalyzer, choose_bucket
from sniffdash.analysis.base import AnalysisContext, AnalysisOptions
from sniffdash.domain.models import Endpoint, Frame, Transport
from sniffdash.repository import InMemoryFrameRepository


def frame(n, ts, src, dst, proto="tcp", length=100):
    return Frame(number=n, timestamp=ts, length=length, protocols=("eth", "ip", proto),
                 highest_protocol=proto, src=Endpoint(src, 1), dst=Endpoint(dst, 2),
                 transport=Transport.TCP, stream_id=0)


@pytest.fixture
def repo():
    return InMemoryFrameRepository([
        frame(1, 10.0, "10.0.0.1", "8.8.8.8", "dns", 80),
        frame(2, 10.1, "10.0.0.1", "1.1.1.1", "http", 500),
        frame(3, 10.2, "10.0.0.2", "1.1.1.1", "tcp", 60),
        frame(4, 12.5, "10.0.0.1", "1.1.1.1", "tcp", 60),   # 2 s of silence before this frame
        Frame(number=5, timestamp=12.6, length=42, protocols=("eth", "arp"), highest_protocol="arp"),
    ])


def ctx(**options):
    return AnalysisContext(AnalysisOptions(**options))


class TestSummary:
    def test_totals_and_time_range(self, repo):
        s = SummaryAnalyzer().analyze(repo, ctx())
        assert (s.packet_count, s.total_bytes) == (5, 742)
        assert (s.start_ts, s.end_ts) == (10.0, 12.6)
        assert s.duration_s == pytest.approx(2.6)

    def test_top_talkers_exclude_non_ip_frames(self, repo):
        s = SummaryAnalyzer().analyze(repo, ctx())
        assert s.top_sources == (("10.0.0.1", 3), ("10.0.0.2", 1))   # ARP frame not counted
        assert s.top_destinations[0] == ("1.1.1.1", 3)

    def test_top_n_limit(self, repo):
        assert len(SummaryAnalyzer().analyze(repo, ctx(top_n=1)).top_sources) == 1

    def test_protocol_distribution_sums_to_packet_count(self, repo):
        s = SummaryAnalyzer().analyze(repo, ctx())
        assert dict(s.protocol_distribution) == {"tcp": 2, "dns": 1, "http": 1, "arp": 1}
        assert sum(c for _, c in s.protocol_distribution) == s.packet_count

    def test_empty_capture(self):
        s = SummaryAnalyzer().analyze(InMemoryFrameRepository([]), ctx())
        assert s.packet_count == 0 and s.start_ts is None and s.top_sources == ()

    def test_ties_are_broken_deterministically(self):
        # Equal counts → alphabetical, so two runs always give the same order.
        assert ranked_counts(pd.Series(["b", "a", "b", "a", "c"])) == (("a", 2), ("b", 2), ("c", 1))


class TestTimeline:
    @pytest.mark.parametrize("duration, max_buckets, expected", [
        (0.0, 200, 0.001), (0.5, 200, 0.01), (2.6, 200, 0.1),
        (3600.0, 200, 60.0), (10.0, 5, 10.0),
    ])
    def test_bucket_choice(self, duration, max_buckets, expected):
        assert choose_bucket(duration, max_buckets) == expected

    def test_totals_preserved_and_silence_kept(self, repo):
        t = TimelineAnalyzer().analyze(repo, ctx())
        assert t.bucket_seconds == 0.1
        assert sum(p for _, p, _ in t.buckets) == 5
        assert sum(b for _, _, b in t.buckets) == 742
        assert len(t.buckets) == 27                       # 10.0 → 12.6 in 0.1 s steps
        assert [p for _, p, _ in t.buckets[3:25]] == [0] * 22   # the 2 s gap is visible

    def test_boundary_timestamp_lands_in_its_own_bucket(self, repo):
        # 10.1 is exactly one bucket after 10.0; float error must not push it back.
        t = TimelineAnalyzer().analyze(repo, ctx())
        assert [p for _, p, _ in t.buckets[:3]] == [1, 1, 1]

    def test_rates(self, repo):
        t = TimelineAnalyzer().analyze(repo, ctx())
        assert t.packets_per_second[0] == pytest.approx(10.0)   # 1 packet / 0.1 s

    def test_bucket_cap_respected(self, repo):
        assert len(TimelineAnalyzer().analyze(repo, ctx(max_timeline_buckets=5)).buckets) <= 5

    def test_empty_capture(self):
        assert TimelineAnalyzer().analyze(InMemoryFrameRepository([]), ctx()).buckets == ()

"""Result containers passed between layers.

* ``ParseOutcome``: produced by the parsing layer (Step 1).
* ``AnalysisResult`` subclasses: produced by analyzers (Step 2). Each subclass
  declares a unique ``key``, and the UI looks up a matching view by result type.
  That is how new analyzers plug in without UI changes (Open/Closed).
* ``AnalysisReport``: the bundle of all results, consumed by the UI and the LLM.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, TypeVar

from sniffdash.domain.errors import IssueSeverity, ParseIssue
from sniffdash.domain.models import Endpoint, Frame, HttpResponse, HttpTransaction

R = TypeVar("R", bound="AnalysisResult")


@dataclass(frozen=True, slots=True)
class ParseOutcome:
    """Everything a parser produced from one file."""

    frames: tuple[Frame, ...]
    issues: tuple[ParseIssue, ...] = ()
    parser_name: str = ""
    source: str = ""
    partial: bool = False  # True when the file ended unexpectedly / was cut short

    @property
    def packet_count(self) -> int:
        return len(self.frames)

    @property
    def has_errors(self) -> bool:
        return any(i.severity is IssueSeverity.ERROR for i in self.issues)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Base class for every analyzer output."""

    key: ClassVar[str] = "base"


@dataclass(frozen=True, slots=True)
class CaptureSummary(AnalysisResult):
    """Global statistics (Reqs 24-25)."""

    key: ClassVar[str] = "summary"

    packet_count: int = 0
    total_bytes: int = 0
    start_ts: float | None = None
    end_ts: float | None = None
    top_sources: tuple[tuple[str, int], ...] = ()
    top_destinations: tuple[tuple[str, int], ...] = ()
    protocol_distribution: tuple[tuple[str, int], ...] = ()

    @property
    def duration_s(self) -> float:
        if self.start_ts is None or self.end_ts is None:
            return 0.0
        return self.end_ts - self.start_ts

    @property
    def start(self) -> datetime | None:
        return None if self.start_ts is None else datetime.fromtimestamp(self.start_ts, tz=timezone.utc)

    @property
    def end(self) -> datetime | None:
        return None if self.end_ts is None else datetime.fromtimestamp(self.end_ts, tz=timezone.utc)


@dataclass(frozen=True, slots=True)
class TrafficTimeline(AnalysisResult):
    """Packets and bytes per fixed time bucket (Req. 26 "traffic over time").

    Empty buckets are kept (zero counts) so a chart shows silences, not a false
    straight line between bursts.
    """

    key: ClassVar[str] = "timeline"

    bucket_seconds: float = 1.0
    buckets: tuple[tuple[float, int, int], ...] = ()  # (bucket start ts, packets, bytes)

    @property
    def packets_per_second(self) -> tuple[float, ...]:
        return tuple(p / self.bucket_seconds for _, p, _ in self.buckets)

    @property
    def bytes_per_second(self) -> tuple[float, ...]:
        return tuple(b / self.bucket_seconds for _, _, b in self.buckets)


@dataclass(frozen=True, slots=True)
class HttpAnalysisResult(AnalysisResult):
    """HTTP transactions after request/response pairing (Reqs 27-29)."""

    key: ClassVar[str] = "http"

    transactions: tuple[HttpTransaction, ...] = ()
    orphan_responses: tuple[HttpResponse, ...] = ()  # responses with no matching request

    @property
    def unanswered(self) -> tuple[HttpTransaction, ...]:
        return tuple(t for t in self.transactions if not t.is_complete)

    def find_by_frame(self, frame_number: int) -> HttpTransaction | None:
        """Find the transaction whose request OR response is in this frame."""
        for tx in self.transactions:
            if tx.request.frame_number == frame_number:
                return tx
            if tx.response and tx.response.frame_number == frame_number:
                return tx
        return None


@dataclass(frozen=True, slots=True)
class EncryptedFlow:
    """Observable metadata of one encrypted (TLS/HTTPS) TCP connection.

    The payload is unreadable, but its *shape* is not: how much flows each way,
    in what sizes, and with what timing. ``label`` is a rule-based INFERENCE from
    these features, and ``reasons`` lists the rule conditions that produced it.
    """

    stream_id: int
    client: Endpoint
    server: Endpoint
    sni: str | None
    first_frame: int
    last_frame: int
    start_ts: float
    end_ts: float
    packets_up: int
    packets_down: int
    bytes_up: int                 # TCP payload bytes, client → server
    bytes_down: int               # TCP payload bytes, server → client
    down_size_mean: float
    down_size_median: float
    down_size_max: int
    iat_mean: float               # inter-arrival time between data packets, seconds
    iat_median: float
    iat_p95: float
    iat_cv: float                 # coefficient of variation (std / mean): 0 = perfectly regular
    burst_count: int
    burst_mean_bytes: float
    largest_burst_share: float    # share of downstream bytes in the largest burst
    burst_interval_cv: float | None  # regularity of burst start times (None: < 3 bursts)
    label: str
    reasons: tuple[str, ...]

    @property
    def duration_s(self) -> float:
        return self.end_ts - self.start_ts

    @property
    def down_up_ratio(self) -> float:
        return self.bytes_down / self.bytes_up if self.bytes_up else float("inf")


@dataclass(frozen=True, slots=True)
class EncryptedFlowsResult(AnalysisResult):
    key: ClassVar[str] = "encrypted_flows"

    flows: tuple[EncryptedFlow, ...] = ()

    def by_label(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for flow in self.flows:
            counts[flow.label] = counts.get(flow.label, 0) + 1
        return dict(sorted(counts.items()))

    def find(self, stream_id: int) -> EncryptedFlow | None:
        return next((f for f in self.flows if f.stream_id == stream_id), None)


@dataclass(frozen=True, slots=True)
class HttpStreamView:
    """One transaction rendered like Wireshark's "Follow HTTP Stream" (Req. 29)."""

    transaction: HttpTransaction
    request_text: str
    response_text: str
    frame_numbers: tuple[int, ...]  # every frame of the TCP stream from request to response


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """All analysis output for one capture."""

    source: str
    summary: CaptureSummary
    results: Mapping[str, AnalysisResult] = field(default_factory=dict)
    issues: tuple[ParseIssue, ...] = ()

    def get(self, result_type: type[R]) -> R | None:
        """Type-safe lookup: ``report.get(HttpAnalysisResult)``."""
        result = self.results.get(result_type.key)
        return result if isinstance(result, result_type) else None

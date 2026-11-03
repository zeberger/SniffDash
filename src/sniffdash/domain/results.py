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
from sniffdash.domain.models import Frame, HttpResponse, HttpTransaction

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

"""Analyzer (Strategy) + AnalyzerRegistry (auto-discovering Registry).

Every analysis — global metrics, the traffic timeline, HTTP transactions, and in
future assignments DNS or TLS — implements ONE interface: take the read-only
``FrameRepository``, return one ``AnalysisResult``. The engine runs whatever is
registered, so adding an analysis means adding a module to
``sniffdash/analysis/analyzers/``; no engine or UI code changes (Open/Closed).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, TypeVar

from sniffdash.domain.errors import IssueSeverity, ParseIssue
from sniffdash.domain.results import AnalysisResult
from sniffdash.plugins import LazyDiscovery
from sniffdash.repository.base import FrameRepository


@dataclass(frozen=True, slots=True)
class AnalysisOptions:
    top_n: int = 10                  # how many top source / destination IPs to keep
    max_timeline_buckets: int = 200  # upper bound for the traffic-over-time series


@dataclass(slots=True)
class AnalysisContext:
    """Per-run state handed to every analyzer: options in, issues out (Notification)."""

    options: AnalysisOptions = field(default_factory=AnalysisOptions)
    issues: list[ParseIssue] = field(default_factory=list)

    def warn(self, message: str, frame_number: int | None = None,
             severity: IssueSeverity = IssueSeverity.WARNING) -> None:
        self.issues.append(ParseIssue(message, severity, frame_number))


class Analyzer(ABC):
    key: ClassVar[str]  # must equal the key of the AnalysisResult it returns

    @abstractmethod
    def analyze(self, repo: FrameRepository, ctx: AnalysisContext) -> AnalysisResult:
        """Compute one result. May record non-fatal problems with ``ctx.warn``."""


A = TypeVar("A", bound=type[Analyzer])


class AnalyzerRegistry:
    def __init__(self, package: str | None = None) -> None:
        self._classes: list[type[Analyzer]] = []
        self._discovery = LazyDiscovery(package)

    def register(self, cls: A) -> A:
        if any(existing.key == cls.key and existing is not cls for existing in self._classes):
            raise ValueError(f"Duplicate analyzer key '{cls.key}'")
        if cls not in self._classes:
            self._classes.append(cls)
        return cls

    def registered(self) -> tuple[type[Analyzer], ...]:
        self._discovery.ensure()
        return tuple(sorted(self._classes, key=lambda c: c.key))  # deterministic run order

    def create_all(self) -> list[Analyzer]:
        return [cls() for cls in self.registered()]


analyzer_registry = AnalyzerRegistry("sniffdash.analysis.analyzers")

register_analyzer: Callable[[A], A] = analyzer_registry.register

"""PacketParser: the parsing abstraction (Template Method pattern).

``parse()`` is a *template*: it fixes the algorithm that every backend must
follow, and delegates only the backend-specific steps to subclasses:

    validate format → scan integrity → for each raw packet:
        read metadata (abstract) → run extractors → post-process (hook)
        → assemble Frame → collect issues
    → ParseOutcome

All the robustness rules (skip bad packets, keep partial results, never crash
the UI) therefore live here ONCE, and both backends inherit them. This is what
makes PyShark and Scapy substitutable (Liskov).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Generic

from sniffdash.domain.errors import CaptureError, CorruptCaptureError, IssueSeverity, ParseIssue
from sniffdash.domain.models import Frame
from sniffdash.domain.results import ParseOutcome
from sniffdash.parsing.assembler import FrameAssembler
from sniffdash.parsing.extractors.base import Backend, LayerExtractor, PacketT, extractor_registry
from sniffdash.parsing.formats import scan_integrity
from sniffdash.parsing.options import ParserOptions


@dataclass(frozen=True, slots=True)
class RawFrameMeta:
    """Backend-neutral metadata every backend must supply for each packet."""

    number: int
    timestamp: float
    length: int
    protocols: tuple[str, ...]


class PacketParser(ABC, Generic[PacketT]):
    name: ClassVar[str]
    backend: ClassVar[Backend]

    def __init__(self, options: ParserOptions | None = None,
                 extractors: Sequence[LayerExtractor] | None = None) -> None:
        self._options = options or ParserOptions()
        # Dependency Injection: tests (or callers) may pass their own extractors;
        # by default we use every extractor registered for this backend.
        self._extractors = (list(extractors) if extractors is not None
                            else extractor_registry.create_all(self.backend, self._options))
        self._assembler = FrameAssembler()

    # --- Abstract / hook steps (implemented by backends) -------------------------

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """True if this backend's dependencies are installed."""

    @abstractmethod
    def _iter_raw_packets(self, path: Path) -> Iterator[PacketT]:
        """Yield the backend's native packet objects, in file order."""

    @abstractmethod
    def _read_meta(self, packet: PacketT, index: int) -> RawFrameMeta:
        """Frame number, timestamp, length and protocol stack of one packet."""

    def _post_process(self, packet: PacketT, layers: dict[str, dict[str, Any]]) -> None:
        """Hook: adjust extracted layers in place (default: nothing)."""

    def _packet_issues(self, packet: PacketT, meta: RawFrameMeta) -> list[ParseIssue]:
        """Hook: backend-specific per-packet warnings (default: none)."""
        return []

    # --- Template method --------------------------------------------------------

    def parse(self, path: Path) -> ParseOutcome:
        path = Path(path)
        integrity = scan_integrity(path)  # also validates format; raises typed errors
        frames: list[Frame] = []
        issues: list[ParseIssue] = []
        partial = False
        limit = self._options.max_packets

        if integrity.truncated:
            partial = True
            issues.append(ParseIssue(
                f"Capture file is truncated ({integrity.detail}); "
                f"only {integrity.complete_records} complete packets are guaranteed.",
                IssueSeverity.ERROR,
            ))

        try:
            with closing(self._iter_raw_packets(path)) as packets:
                for index, packet in enumerate(packets, start=1):
                    if limit is not None and index > limit:
                        partial = True
                        issues.append(ParseIssue(
                            f"Stopped after {limit} packets (max_packets limit).", IssueSeverity.INFO))
                        break
                    try:
                        frame, frame_issues = self._build_frame(packet, index)
                    except Exception as exc:  # one bad packet must never abort the parse
                        issues.append(ParseIssue(f"Packet could not be decoded: {exc}",
                                                 IssueSeverity.WARNING, index))
                        continue
                    frames.append(frame)
                    issues.extend(frame_issues)
        except CaptureError:
            raise
        except Exception as exc:
            # The backend died mid-file. Keep what we have, unless we have nothing.
            if not frames:
                raise CorruptCaptureError(f"'{path.name}' could not be parsed: {exc}") from exc
            partial = True
            if not integrity.truncated:  # avoid reporting the same cause twice
                issues.append(ParseIssue(
                    f"Parsing stopped unexpectedly after frame {frames[-1].number}: {exc}",
                    IssueSeverity.ERROR))

        if not frames and not partial:
            issues.append(ParseIssue("Capture contains no packets.", IssueSeverity.INFO))

        return ParseOutcome(frames=tuple(frames), issues=tuple(issues), parser_name=self.name,
                            source=path.name, partial=partial)

    def _build_frame(self, packet: PacketT, index: int) -> tuple[Frame, list[ParseIssue]]:
        meta = self._read_meta(packet, index)
        issues = self._packet_issues(packet, meta)
        layers: dict[str, dict[str, Any]] = {}
        for extractor in self._extractors:
            try:
                if extractor.applies_to(packet):
                    layers[extractor.layer] = extractor.extract(packet)
            except Exception as exc:  # a broken layer loses that layer, not the frame
                issues.append(ParseIssue(f"{extractor.layer.upper()} fields could not be decoded: {exc}",
                                         IssueSeverity.WARNING, meta.number))
        self._post_process(packet, layers)
        frame = self._assembler.assemble(number=meta.number, timestamp=meta.timestamp,
                                         length=meta.length, protocols=meta.protocols, layers=layers)
        return frame, issues

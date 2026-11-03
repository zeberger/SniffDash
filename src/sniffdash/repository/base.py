"""FrameRepository: the data-access abstraction (Repository pattern).

Analyzers, the LLM tools and the UI ask *questions* about frames ("give me frame
42", "all HTTP frames", "everything in TCP stream 3"). They never learn how
frames are stored. Today that is an in-memory dict. For multi-GB captures, a
SQLite/DuckDB-backed repository can replace it without touching any caller
(Dependency Inversion).

The interface is read-only on purpose (Interface Segregation). Nothing above the
parsing layer should ever add or modify frames.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from sniffdash.domain.errors import FrameNotFoundError
from sniffdash.domain.models import Frame, Transport

if TYPE_CHECKING:  # pandas is only needed by implementations, not by the interface
    import pandas as pd


class FrameRepository(ABC):
    @abstractmethod
    def __len__(self) -> int: ...

    @abstractmethod
    def __contains__(self, number: object) -> bool: ...

    @abstractmethod
    def get(self, number: int) -> Frame | None:
        """Frame by Wireshark frame number, or None."""

    @abstractmethod
    def iter(self, protocol: str | None = None) -> Iterator[Frame]:
        """All frames in frame-number order, optionally only those carrying ``protocol``."""

    @abstractmethod
    def by_stream(self, transport: Transport, stream_id: int) -> list[Frame]:
        """All frames of one TCP/UDP conversation, in order (basis for "Follow Stream")."""

    @abstractmethod
    def protocols(self) -> frozenset[str]:
        """Every protocol name seen anywhere in the capture."""

    @abstractmethod
    def time_range(self) -> tuple[float, float] | None:
        """(earliest, latest) timestamp, or None for an empty capture."""

    @abstractmethod
    def to_dataframe(self) -> pd.DataFrame:
        """Flat tabular view (one row per frame) for Pandas/Plotly."""

    # --- Concrete conveniences built only on the abstract API -------------------

    def require(self, number: int) -> Frame:
        """Like ``get`` but raises ``FrameNotFoundError``. Used to validate citations."""
        frame = self.get(number)
        if frame is None:
            raise FrameNotFoundError(f"Frame {number} does not exist in this capture")
        return frame

    def get_many(self, numbers: Iterable[int]) -> list[Frame]:
        """Existing frames among ``numbers``, in the given order; missing ones skipped."""
        return [f for n in numbers if (f := self.get(n)) is not None]

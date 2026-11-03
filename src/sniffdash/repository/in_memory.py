"""InMemoryFrameRepository: dict-backed FrameRepository with prebuilt indexes.

Indexes are built once in ``__init__`` (O(n)), so every query is an O(1) dict
lookup plus iteration over the matches. The DataFrame is built lazily, on first
request, and cached. Frames are immutable, so the cache can never go stale.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator

import pandas as pd

from sniffdash.domain.errors import DuplicateFrameError
from sniffdash.domain.models import Frame, Transport
from sniffdash.domain.results import ParseOutcome
from sniffdash.repository.base import FrameRepository

FRAME_COLUMNS: tuple[str, ...] = (
    "number", "timestamp", "time", "length", "src_ip", "src_port", "dst_ip", "dst_port",
    "transport", "stream_id", "protocol", "protocols",
)


class InMemoryFrameRepository(FrameRepository):
    def __init__(self, frames: Iterable[Frame]) -> None:
        self._frames: dict[int, Frame] = {}
        for frame in sorted(frames, key=lambda f: f.number):
            if frame.number in self._frames:
                raise DuplicateFrameError(f"Duplicate frame number {frame.number}")
            self._frames[frame.number] = frame

        self._by_protocol: dict[str, list[int]] = defaultdict(list)
        self._by_stream: dict[tuple[Transport, int], list[int]] = defaultdict(list)
        for frame in self._frames.values():
            for proto in dict.fromkeys(frame.protocols):  # de-duplicated, order kept
                self._by_protocol[proto].append(frame.number)
            if frame.transport is not None and frame.stream_id is not None:
                self._by_stream[(frame.transport, frame.stream_id)].append(frame.number)

        timestamps = [f.timestamp for f in self._frames.values()]
        self._time_range = (min(timestamps), max(timestamps)) if timestamps else None
        self._dataframe: pd.DataFrame | None = None

    @classmethod
    def from_outcome(cls, outcome: ParseOutcome) -> InMemoryFrameRepository:
        return cls(outcome.frames)

    def __len__(self) -> int:
        return len(self._frames)

    def __contains__(self, number: object) -> bool:
        return number in self._frames

    def get(self, number: int) -> Frame | None:
        return self._frames.get(number)

    def iter(self, protocol: str | None = None) -> Iterator[Frame]:
        if protocol is None:
            return iter(self._frames.values())
        return (self._frames[n] for n in self._by_protocol.get(protocol.lower(), ()))

    def by_stream(self, transport: Transport, stream_id: int) -> list[Frame]:
        return [self._frames[n] for n in self._by_stream.get((transport, stream_id), ())]

    def protocols(self) -> frozenset[str]:
        return frozenset(self._by_protocol)

    def time_range(self) -> tuple[float, float] | None:
        # min/max rather than first/last: real captures can be slightly out of order.
        return self._time_range

    def to_dataframe(self) -> pd.DataFrame:
        if self._dataframe is None:
            self._dataframe = self._build_dataframe()
        return self._dataframe.copy()  # callers may mutate their copy safely

    def _build_dataframe(self) -> pd.DataFrame:
        rows = [
            {
                "number": f.number,
                "timestamp": f.timestamp,
                "length": f.length,
                "src_ip": f.src.ip if f.src else None,
                "src_port": f.src.port if f.src else None,
                "dst_ip": f.dst.ip if f.dst else None,
                "dst_port": f.dst.port if f.dst else None,
                "transport": f.transport.value if f.transport else None,
                "stream_id": f.stream_id,
                "protocol": f.highest_protocol,
                "protocols": ":".join(f.protocols),
            }
            for f in self._frames.values()
        ]
        df = pd.DataFrame(rows, columns=[c for c in FRAME_COLUMNS if c != "time"])
        df.insert(2, "time", pd.to_datetime(df["timestamp"], unit="s", utc=True))
        # Nullable integer dtype: ports/stream ids can be missing (ARP, ICMP...).
        for col in ("src_port", "dst_port", "stream_id"):
            df[col] = df[col].astype("Int64")
        return df

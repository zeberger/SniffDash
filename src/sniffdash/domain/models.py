"""Core domain models (Value Objects).

All models are frozen dataclasses: once a frame is parsed it never changes.
Immutability matters for two reasons:

1. **Correctness:** analyzers share the same Frame objects; none of them can
   corrupt data another analyzer relies on.
2. **Caching:** Streamlit caches parsed captures between re-renders. Cached
   objects must not be mutated, and must be picklable for ``st.cache_data``.
   That is why we use our own picklable ``FrozenMap`` instead of
   ``types.MappingProxyType``, which cannot be pickled.

Timestamps are stored as ``float`` epoch seconds (what pcap stores). They are
cheap to subtract for response times, and ``.datetime`` converts for display.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


# --- Helpers -------------------------------------------------------------------------

class FrozenMap(Mapping[str, Any]):
    """A small, read-only, picklable mapping.

    Nested dicts become FrozenMaps and lists become tuples, so the whole
    structure is deeply immutable.
    """

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = {k: _freeze(v) for k, v in (data or {}).items()}

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenMap({self._data!r})"

    def __reduce__(self):  # makes pickling work despite __slots__ and no setters
        return (FrozenMap, (self._data,))

    def __hash__(self) -> int:
        return hash(tuple(sorted(self._data.items(), key=lambda kv: kv[0])))


def _freeze(value: Any) -> Any:
    if isinstance(value, FrozenMap):
        return value
    if isinstance(value, Mapping):
        return FrozenMap(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


# --- Network primitives ---------------------------------------------------------------

class Transport(StrEnum):
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True, slots=True, order=True)
class Endpoint:
    """One side of a conversation: an IP address and (optionally) a port."""

    ip: str
    port: int | None = None

    def __str__(self) -> str:
        if self.port is None:
            return self.ip
        host = f"[{self.ip}]" if ":" in self.ip else self.ip  # IPv6 needs brackets
        return f"{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class Frame:
    """One captured frame, normalized and independent of the parser backend.

    ``number`` is 1-based and identical to Wireshark's "No." column; it is the
    anchor the LLM cites as evidence. ``layers`` holds the per-protocol fields
    produced by the extractors (schema documented in ``parsing.extractors.base``).
    """

    number: int
    timestamp: float
    length: int
    protocols: tuple[str, ...] = ()
    highest_protocol: str = "unknown"
    src: Endpoint | None = None
    dst: Endpoint | None = None
    transport: Transport | None = None
    stream_id: int | None = None
    layers: Mapping[str, Mapping[str, Any]] = field(default_factory=FrozenMap, repr=False)

    def __post_init__(self) -> None:
        if self.number < 1:
            raise ValueError(f"Frame number must be >= 1, got {self.number}")
        if self.length < 0:
            raise ValueError(f"Frame length must be >= 0, got {self.length}")
        # Frozen dataclasses forbid normal assignment; object.__setattr__ is the
        # documented way to normalize fields during construction.
        object.__setattr__(self, "protocols", tuple(p.lower() for p in self.protocols))
        object.__setattr__(self, "highest_protocol", self.highest_protocol.lower())
        object.__setattr__(self, "layers", FrozenMap(self.layers))

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    def has_protocol(self, name: str) -> bool:
        return name.lower() in self.protocols

    def layer(self, name: str) -> Mapping[str, Any] | None:
        return self.layers.get(name.lower())


# --- HTTP ------------------------------------------------------------------------------

class StatusClass(StrEnum):
    INFORMATIONAL = "1xx"
    SUCCESS = "2xx"
    REDIRECTION = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"

    @classmethod
    def from_code(cls, code: int) -> StatusClass:
        if not 100 <= code <= 599:
            raise ValueError(f"Invalid HTTP status code: {code}")
        return list(cls)[code // 100 - 1]


@dataclass(frozen=True, slots=True, kw_only=True)
class HttpMessage:
    """Fields shared by requests and responses (base class, DRY)."""

    frame_number: int
    timestamp: float
    src: Endpoint
    dst: Endpoint
    version: str = "HTTP/1.1"
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""
    stream_id: int | None = None

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
        wanted = name.lower()
        return next((v for k, v in self.headers if k.lower() == wanted), None)

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)


@dataclass(frozen=True, slots=True, kw_only=True)
class HttpRequest(HttpMessage):
    method: str
    uri: str
    host: str | None = None

    @property
    def effective_host(self) -> str:
        """Host to display: Host field, then Host header, then destination IP.

        The fallback chain handles HTTP/1.0 requests and malformed captures that
        lack a Host header.
        """
        return self.host or self.header("Host") or self.dst.ip


@dataclass(frozen=True, slots=True, kw_only=True)
class HttpResponse(HttpMessage):
    status_code: int
    reason: str = ""

    def __post_init__(self) -> None:
        StatusClass.from_code(self.status_code)  # validates range, raises ValueError

    @property
    def status_class(self) -> StatusClass:
        return StatusClass.from_code(self.status_code)

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400


@dataclass(frozen=True, slots=True)
class HttpTransaction:
    """A request paired with its response (``response`` is None when unanswered)."""

    id: str
    request: HttpRequest
    response: HttpResponse | None = None

    def __post_init__(self) -> None:
        if self.response is not None and self.response.timestamp < self.request.timestamp:
            raise ValueError(
                f"Transaction {self.id}: response frame {self.response.frame_number} "
                f"precedes request frame {self.request.frame_number}"
            )

    @property
    def is_complete(self) -> bool:
        return self.response is not None

    @property
    def response_time_ms(self) -> float | None:
        """Request→response delta in milliseconds (Req. 28), or None if unanswered."""
        if self.response is None:
            return None
        return (self.response.timestamp - self.request.timestamp) * 1000.0

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response else None

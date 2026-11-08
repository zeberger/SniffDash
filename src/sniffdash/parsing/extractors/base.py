"""LayerExtractor (Strategy) + ExtractorRegistry (auto-discovering Registry).

An extractor knows how to pull the fields of ONE protocol out of ONE backend's
packet object, and returns them in a backend-neutral dict. That dict schema is
the contract between the parsing layer and everything above it:

=========  =====================================================================
layer key  fields (missing values are None)
=========  =====================================================================
ip         src, dst, version (4|6), ttl
tcp        srcport, dstport, stream, seq, ack, flags, payload_len
udp        srcport, dstport, stream
http       kind ("request"|"response"), method, uri, host, version,
           status_code, reason, headers [(name, value)...], body,
           request_in, response_in (tshark's hints; NOT used for pairing, since
           they mispair pipelined requests), time (tshark's delta, seconds),
           extra_messages [same schema...] (2nd+ message in one segment; PyShark only)
dns        id, is_response, qname, qtype, rcode, answers [str...]
tls        content_type, handshake_type, version, sni
=========  =====================================================================

**How to add a protocol** (Open/Closed): create ``extractors/<proto>.py`` with
classes decorated by ``@extractor_registry.register(Backend.X)``. Modules in this
package are discovered automatically; no other file changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from enum import StrEnum
from typing import Any, ClassVar, Generic, TypeVar

from sniffdash.parsing.options import ParserOptions
from sniffdash.plugins import LazyDiscovery

PacketT = TypeVar("PacketT")


class Backend(StrEnum):
    PYSHARK = "pyshark"
    SCAPY = "scapy"


class LayerExtractor(ABC, Generic[PacketT]):
    """Extract one protocol's fields from one backend's packet object."""

    layer: ClassVar[str]  # key under which the result is stored in Frame.layers

    def __init__(self, options: ParserOptions) -> None:
        self._options = options

    @abstractmethod
    def applies_to(self, packet: PacketT) -> bool:
        """Cheap check: does this packet carry the protocol?"""

    @abstractmethod
    def extract(self, packet: PacketT) -> dict[str, Any]:
        """Return the normalized field dict (see module docstring)."""


E = TypeVar("E", bound=type[LayerExtractor])


class ExtractorRegistry:
    def __init__(self, package: str | None = None) -> None:
        self._by_backend: dict[Backend, list[type[LayerExtractor]]] = {b: [] for b in Backend}
        self._discovery = LazyDiscovery(package)

    def register(self, backend: Backend) -> Callable[[E], E]:
        def decorator(cls: E) -> E:
            if cls not in self._by_backend[backend]:
                self._by_backend[backend].append(cls)
            return cls
        return decorator

    def create_all(self, backend: Backend, options: ParserOptions) -> list[LayerExtractor]:
        self._discovery.ensure()
        return [cls(options) for cls in self._by_backend[backend]]

    def registered(self, backend: Backend) -> tuple[type[LayerExtractor], ...]:
        self._discovery.ensure()
        return tuple(self._by_backend[backend])


extractor_registry = ExtractorRegistry("sniffdash.parsing.extractors")


# --- Shared helpers for concrete extractors ---------------------------------------

def decode_body(raw: bytes | str | None, limit: int) -> str:
    """Bytes → text for display. Never raises; binary content is replaced."""
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    return text if len(text) <= limit else text[:limit] + f"\n… [truncated, {len(text)} chars total]"


def parse_header_lines(lines: Iterable[str]) -> list[tuple[str, str]]:
    """'Name: value\\r\\n' lines → [(name, value)]; tolerant of junk lines."""
    headers: list[tuple[str, str]] = []
    for line in lines:
        name, sep, value = str(line).partition(":")
        if sep and name.strip():
            headers.append((name.strip(), value.strip()))
    return headers


def to_int(value: Any) -> int | None:
    """'80' → 80, '0x1234' → 4660, junk/None → None."""
    if value is None or value == "":
        return None
    text = str(value).strip()
    try:
        return int(text)
    except ValueError:
        try:
            return int(text, 16) if text.lower().startswith("0x") else None
        except ValueError:
            return None


def to_bool(value: Any) -> bool | None:
    """tshark booleans arrive as 'True'/'False' or '1'/'0'."""
    if value is None:
        return None
    return str(value).strip().lower() in {"true", "1", "yes"}


def tshark_bytes(value: Any) -> bytes | None:
    """tshark renders byte fields as '3c:68:74' hex; fall back to raw text."""
    if value is None:
        return None
    text = str(value)
    try:
        return bytes.fromhex(text.replace(":", ""))
    except ValueError:
        return text.encode("utf-8", errors="replace")


# --- PyShark field access (shared by all pyshark extractors) --------------------------

def pyshark_has_layer(packet: Any, name: str) -> bool:
    return any(layer.layer_name == name for layer in packet.layers)


def pyshark_field(layer: Any, name: str) -> str | None:
    value = layer.get_field_value(name)
    return None if value is None else str(value)


def pyshark_all_values(layer: Any, name: str) -> list[str]:
    """Every occurrence of a repeated field (e.g. one per HTTP header line)."""
    field = layer.get_field(name)
    if field is None:
        return []
    return [str(getattr(f, "show", f)) for f in getattr(field, "all_fields", [field])]

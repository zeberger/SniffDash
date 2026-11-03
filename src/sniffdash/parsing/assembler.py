"""FrameAssembler: builds a domain ``Frame`` from backend-neutral pieces.

Both backends produce the same inputs (frame metadata + normalized layer dicts).
This class turns them into a ``Frame``, so the rules that decide the endpoints,
the stream id and the "highest protocol" exist in exactly one place.
That guarantees both backends classify traffic identically.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sniffdash.domain.models import Endpoint, Frame, Transport

# Protocol names that describe the *content format* of a payload, not a protocol.
# Wireshark reports e.g. "data-text-lines" as the top layer of an HTML response;
# for statistics we want to count that frame as "http". Extend freely.
PAYLOAD_FORMATS: frozenset[str] = frozenset({
    "data", "data-text-lines", "media", "json", "xml", "urlencoded-form",
    "mime_multipart", "png", "image-gif", "image-jfif", "text", "padding",
    "ethertype", "_ws.malformed", "_ws.short", "raw",
})


def _to_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


class FrameAssembler:
    def assemble(
        self,
        *,
        number: int,
        timestamp: float,
        length: int,
        protocols: tuple[str, ...],
        layers: Mapping[str, Mapping[str, Any]],
    ) -> Frame:
        protocols = tuple(p.lower() for p in protocols if p)
        ip = layers.get("ip") or {}
        transport, t_layer = self._transport(layers)

        src = dst = None
        if ip.get("src") and ip.get("dst"):
            src = Endpoint(str(ip["src"]), _to_int(t_layer.get("srcport")))
            dst = Endpoint(str(ip["dst"]), _to_int(t_layer.get("dstport")))

        return Frame(
            number=number,
            timestamp=timestamp,
            length=length,
            protocols=protocols,
            highest_protocol=self.highest_protocol(protocols),
            src=src,
            dst=dst,
            transport=transport,
            stream_id=_to_int(t_layer.get("stream")),
            layers=layers,
        )

    @staticmethod
    def highest_protocol(protocols: tuple[str, ...]) -> str:
        """The top-most *real* protocol in the stack (payload formats skipped)."""
        for proto in reversed(protocols):
            if proto not in PAYLOAD_FORMATS:
                return proto
        return protocols[-1] if protocols else "unknown"

    @staticmethod
    def _transport(layers: Mapping[str, Mapping[str, Any]]) -> tuple[Transport | None, Mapping[str, Any]]:
        if "tcp" in layers:
            return Transport.TCP, layers["tcp"]
        if "udp" in layers:
            return Transport.UDP, layers["udp"]
        return None, {}

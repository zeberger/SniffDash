"""Build domain HTTP messages from the normalized ``http`` layer of each frame.

Two robustness rules live here, before pairing ever sees a message:

* A message that cannot become a valid domain object (no method, impossible
  status code, no TCP stream) is skipped with a WARNING naming its frame.
* A **retransmitted** segment carries the same bytes again. Scapy (no TCP
  analysis) decodes it as a second HTTP message, which would sit in the pairing
  queue as a ghost request and shift every later pair on that connection. It is
  recognized by (stream, sender, TCP sequence number, position in segment) and dropped.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sniffdash.analysis.base import AnalysisContext
from sniffdash.domain.errors import IssueSeverity
from sniffdash.domain.models import Frame, HttpRequest, HttpResponse
from sniffdash.repository.base import FrameRepository


@dataclass(frozen=True, slots=True)
class SequencedMessage:
    """A message plus its position, so ordering is exact even with 2 messages in one frame."""

    message: HttpRequest | HttpResponse
    frame_number: int
    position: int  # 0 = first HTTP message in the segment


def _headers(raw: Any) -> tuple[tuple[str, str], ...]:
    return tuple((str(name), str(value)) for name, value in (raw or ()))


def _build(frame: Frame, msg: Mapping[str, Any]) -> HttpRequest | HttpResponse:
    common = dict(
        frame_number=frame.number,
        timestamp=frame.timestamp,
        src=frame.src,
        dst=frame.dst,
        version=msg.get("version") or "HTTP/1.1",
        headers=_headers(msg.get("headers")),
        body=msg.get("body") or "",
        stream_id=frame.stream_id,
    )
    if msg["kind"] == "request":
        if not msg.get("method"):
            raise ValueError("request without a method")
        return HttpRequest(**common, method=str(msg["method"]), uri=str(msg.get("uri") or ""),
                           host=msg.get("host"))
    if msg.get("status_code") is None:
        raise ValueError("response without a status code")
    return HttpResponse(**common, status_code=int(msg["status_code"]), reason=msg.get("reason") or "")


def build_messages(repo: FrameRepository, ctx: AnalysisContext) -> list[SequencedMessage]:
    out: list[SequencedMessage] = []
    seen: set[tuple] = set()
    for frame in repo.iter("http"):
        layer = frame.layer("http")
        if layer is None:
            continue
        candidates = [layer, *(layer.get("extra_messages") or ())]
        for position, msg in enumerate(candidates):
            if msg.get("kind") not in ("request", "response"):
                continue  # body continuation segment
            if frame.stream_id is None or frame.src is None or frame.dst is None:
                ctx.warn("HTTP message outside a TCP stream ignored.", frame.number)
                continue
            seq = (frame.layer("tcp") or {}).get("seq")
            if seq is not None:
                fingerprint = (frame.stream_id, frame.src, seq, position)
                if fingerprint in seen:
                    ctx.warn("Retransmitted HTTP message ignored.", frame.number, IssueSeverity.INFO)
                    continue
                seen.add(fingerprint)
            try:
                out.append(SequencedMessage(_build(frame, msg), frame.number, position))
            except (ValueError, TypeError) as exc:
                ctx.warn(f"Malformed HTTP {msg.get('kind')} skipped: {exc}", frame.number)
    return out

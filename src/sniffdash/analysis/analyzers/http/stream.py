"""HttpStreamReconstructor: render one transaction like Wireshark's "Follow HTTP Stream" (Req. 29).

Computed on demand (when the user opens a transaction), not for every transaction
up front: most transactions are never opened.
"""

from __future__ import annotations

from sniffdash.domain.models import HttpMessage, HttpTransaction, Transport
from sniffdash.domain.results import HttpStreamView
from sniffdash.repository.base import FrameRepository

NO_RESPONSE = "(no response captured)"


def _render(start_line: str, message: HttpMessage) -> str:
    lines = [start_line, *(f"{name}: {value}" for name, value in message.headers), ""]
    if message.body:
        lines.append(message.body)
    return "\r\n".join(lines)


class HttpStreamReconstructor:
    def reconstruct(self, tx: HttpTransaction, repo: FrameRepository) -> HttpStreamView:
        req, resp = tx.request, tx.response
        request_text = _render(f"{req.method} {req.uri} {req.version}", req)
        response_text = (_render(f"{resp.version} {resp.status_code} {resp.reason}".rstrip(), resp)
                         if resp else NO_RESPONSE)

        last = resp.frame_number if resp else req.frame_number
        frames: tuple[int, ...] = ()
        if req.stream_id is not None:
            frames = tuple(f.number for f in repo.by_stream(Transport.TCP, req.stream_id)
                           if req.frame_number <= f.number <= last)
        return HttpStreamView(transaction=tx, request_text=request_text,
                              response_text=response_text, frame_numbers=frames)

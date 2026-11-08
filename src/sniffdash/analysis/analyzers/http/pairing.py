"""Pair HTTP requests with responses: stream ID first, then FIFO (RFC 9112 §9.3.2).

HTTP/1.1 guarantees that responses on one connection arrive in the same order as
the requests. So the rule is:

1. **Partition by TCP stream ID.** Pairing never crosses connections, however
   dense or interleaved the capture is.
2. **Inside one stream, FIFO:** each final response answers the oldest unanswered
   request sent in the opposite direction.

Why not trust tshark's own ``response_in`` links? A probe with two pipelined
requests showed tshark pairs the first response with the SECOND request. FIFO is
correct by protocol definition and identical for both parser backends.

Special cases:
* Interim responses 100/102/103 precede the real answer, so they don't consume the
  request. 101 (Switching Protocols) IS the final answer to an upgrade request.
* A response with no pending request is an *orphan* (its request was not captured).
* A response timestamped before its request indicates a capture anomaly. It
  becomes an orphan with a warning and the request stays pending (never a crash).
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from sniffdash.analysis.analyzers.http.messages import SequencedMessage
from sniffdash.domain.errors import IssueSeverity, ParseIssue
from sniffdash.domain.models import HttpRequest, HttpResponse, HttpTransaction

INTERIM_STATUS = frozenset({100, 102, 103})


@dataclass(slots=True)
class PairingResult:
    transactions: list[HttpTransaction] = field(default_factory=list)
    orphans: list[HttpResponse] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)


def pair_by_stream(messages: Iterable[SequencedMessage]) -> PairingResult:
    result = PairingResult()
    by_stream: dict[int, list[SequencedMessage]] = defaultdict(list)
    for item in messages:
        by_stream[item.message.stream_id].append(item)

    paired: list[tuple[SequencedMessage, HttpResponse | None]] = []
    for stream_id in sorted(by_stream):
        items = sorted(by_stream[stream_id], key=lambda m: (m.frame_number, m.position))
        pending: deque[SequencedMessage] = deque()
        for item in items:
            msg = item.message
            if isinstance(msg, HttpRequest):
                pending.append(item)
                continue
            if msg.status_code in INTERIM_STATUS:
                continue
            match = next((p for p in pending
                          if p.message.dst == msg.src and p.message.src == msg.dst), None)
            if match is None:
                result.orphans.append(msg)
                continue
            if msg.timestamp < match.message.timestamp:
                result.orphans.append(msg)
                result.issues.append(ParseIssue(
                    f"Response timestamped before its request (frame {match.frame_number}); left unpaired.",
                    IssueSeverity.WARNING, msg.frame_number))
                continue
            pending.remove(match)
            paired.append((match, msg))
        paired.extend((item, None) for item in pending)  # never answered

    paired.sort(key=lambda pair: (pair[0].frame_number, pair[0].position))
    for request_item, response in paired:
        suffix = f".{request_item.position}" if request_item.position else ""
        result.transactions.append(HttpTransaction(
            f"tx-{request_item.frame_number}{suffix}", request_item.message, response))
    return result

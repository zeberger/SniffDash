"""Tunable parser settings, shared by all backends and extractors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ParserOptions:
    # Stop after this many packets (None = unlimited). Protects the UI from huge captures.
    max_packets: int | None = None
    # Keep at most this many characters of each HTTP body (headers are always kept).
    body_char_limit: int = 16_384

"""Parsing layer: capture file → ParseOutcome (frames + issues)."""

from sniffdash.parsing.base import PacketParser, RawFrameMeta
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.factory import ParserFactory
from sniffdash.parsing.formats import CaptureFormat, IntegrityReport, detect_capture_format, scan_integrity
from sniffdash.parsing.options import ParserOptions

__all__ = [
    "Backend", "CaptureFormat", "IntegrityReport", "PacketParser", "ParserFactory",
    "ParserOptions", "RawFrameMeta", "detect_capture_format", "scan_integrity",
]

"""Unit tests for PacketParser's Template Method, using a FAKE backend.

The fake backend yields plain dicts instead of real packets. That isolates the
robustness rules (skip bad packets, keep partial results, typed errors) from
PyShark/Scapy, so a failure here always points at ``parsing/base.py``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sniffdash.domain.errors import CorruptCaptureError, IssueSeverity
from sniffdash.parsing.base import PacketParser, RawFrameMeta
from sniffdash.parsing.extractors.base import Backend, LayerExtractor
from sniffdash.parsing.options import ParserOptions
from sniffdash.parsing.scapy_parser import StreamIndexer


class DictIpExtractor(LayerExtractor[dict]):
    layer = "ip"

    def applies_to(self, packet: dict) -> bool:
        return "ip" in packet

    def extract(self, packet: dict) -> dict[str, Any]:
        if packet["ip"] == "explode":
            raise RuntimeError("bad IP header")
        return {"src": packet["ip"], "dst": "9.9.9.9"}


class FakeParser(PacketParser[dict]):
    """Yields the given dicts; a dict with crash=True kills the whole iteration."""

    name = "fake"
    backend = Backend.SCAPY

    def __init__(self, packets: list[dict], options: ParserOptions | None = None):
        super().__init__(options, extractors=[DictIpExtractor(options or ParserOptions())])
        self._packets = packets

    @classmethod
    def is_available(cls) -> bool:
        return True

    def _iter_raw_packets(self, path: Path) -> Iterator[dict]:
        for packet in self._packets:
            if packet.get("crash"):
                raise OSError("backend process died")
            yield packet

    def _read_meta(self, packet: dict, index: int) -> RawFrameMeta:
        if packet.get("undecodable"):
            raise ValueError("cannot read timestamp")
        return RawFrameMeta(number=index, timestamp=float(index), length=60, protocols=("eth", "ip"))


def ok(ip: str = "1.1.1.1") -> dict:
    return {"ip": ip}


def test_happy_path(header_only_pcap):
    outcome = FakeParser([ok(), ok("2.2.2.2")]).parse(header_only_pcap)
    assert [f.number for f in outcome.frames] == [1, 2]
    assert outcome.frames[1].src.ip == "2.2.2.2"
    assert outcome.parser_name == "fake" and not outcome.partial and outcome.issues == ()


def test_undecodable_packet_is_skipped_but_numbering_is_preserved(header_only_pcap):
    # Frame 2 is lost, but frame 3 must STILL be number 3 (it is cited as evidence).
    outcome = FakeParser([ok(), {"undecodable": True}, ok()]).parse(header_only_pcap)
    assert [f.number for f in outcome.frames] == [1, 3]
    issue, = outcome.issues
    assert issue.frame_number == 2 and issue.severity is IssueSeverity.WARNING


def test_broken_layer_loses_only_that_layer(header_only_pcap):
    outcome = FakeParser([ok("explode")]).parse(header_only_pcap)
    frame, = outcome.frames
    assert "ip" not in frame.layers and frame.src is None
    assert "IP fields could not be decoded" in outcome.issues[0].message


def test_backend_crash_mid_file_keeps_partial_results(header_only_pcap):
    outcome = FakeParser([ok(), ok(), {"crash": True}, ok()]).parse(header_only_pcap)
    assert len(outcome.frames) == 2
    assert outcome.partial and outcome.has_errors


def test_backend_crash_before_any_frame_is_corrupt(header_only_pcap):
    with pytest.raises(CorruptCaptureError, match="backend process died"):
        FakeParser([{"crash": True}]).parse(header_only_pcap)


def test_max_packets_limit(header_only_pcap):
    outcome = FakeParser([ok()] * 5, ParserOptions(max_packets=3)).parse(header_only_pcap)
    assert len(outcome.frames) == 3 and outcome.partial
    assert outcome.issues[-1].severity is IssueSeverity.INFO


def test_empty_capture_reports_info(header_only_pcap):
    outcome = FakeParser([]).parse(header_only_pcap)
    assert outcome.frames == () and outcome.issues[0].message == "Capture contains no packets."


def test_non_capture_is_rejected_before_backend_runs(garbage_file):
    from sniffdash.domain.errors import UnsupportedFormatError
    with pytest.raises(UnsupportedFormatError):
        FakeParser([ok()]).parse(garbage_file)


class TestStreamIndexer:
    def test_direction_independent(self):
        idx = StreamIndexer()
        a, b = ("10.0.0.2", 50000), ("1.2.3.4", 80)
        assert idx.index("tcp", a, b) == idx.index("tcp", b, a) == 0

    def test_numbering_follows_first_appearance_per_transport(self):
        idx = StreamIndexer()
        assert idx.index("tcp", ("a", 1), ("b", 2)) == 0
        assert idx.index("tcp", ("a", 3), ("b", 2)) == 1
        assert idx.index("udp", ("a", 1), ("b", 2)) == 0  # UDP has its own counter, like tshark

"""Unit tests for extractor helpers, the auto-discovering registry and the assembler."""

from __future__ import annotations

from typing import Any

import pytest

from sniffdash.domain.models import Endpoint, Transport
from sniffdash.parsing.assembler import FrameAssembler
from sniffdash.parsing.extractors.base import (
    Backend, ExtractorRegistry, LayerExtractor, decode_body, extractor_registry,
    parse_header_lines, to_bool, to_int, tshark_bytes,
)
from sniffdash.parsing.extractors.tcp_udp import flags_to_str
from sniffdash.parsing.options import ParserOptions


class TestHelpers:
    @pytest.mark.parametrize("raw, expected", [("80", 80), ("0x1234", 0x1234), ("", None),
                                               (None, None), ("abc", None), (" 7 ", 7)])
    def test_to_int(self, raw, expected):
        assert to_int(raw) == expected

    @pytest.mark.parametrize("raw, expected", [("True", True), ("False", False), ("1", True),
                                               ("0", False), (None, None)])
    def test_to_bool(self, raw, expected):
        assert to_bool(raw) is expected

    def test_tshark_bytes_decodes_colon_hex(self):
        assert tshark_bytes("3c:68:69:3e") == b"<hi>"

    def test_parse_header_lines_tolerates_junk(self):
        lines = ["Host: example.com\r\n", "garbage-without-colon", ": no-name", "X-A:  b:c "]
        # Values may contain ':' (e.g. URLs, times) so only the FIRST colon splits.
        assert parse_header_lines(lines) == [("Host", "example.com"), ("X-A", "b:c")]

    def test_decode_body_truncates_and_replaces_binary(self):
        assert decode_body(b"\xff\xfeabc", 100).endswith("abc")  # invalid UTF-8 → U+FFFD, no crash
        long = decode_body(b"x" * 50, 10)
        assert long.startswith("x" * 10) and "truncated, 50 chars" in long

    def test_tcp_flags(self):
        assert flags_to_str(0x12) == "SA"
        assert flags_to_str(0x18) == "PA"
        assert flags_to_str(None) == ""


class TestRegistry:
    def test_builtin_extractors_are_auto_discovered(self):
        # Proves Open/Closed: no file lists these modules explicitly.
        for backend in Backend:
            layers = {cls.layer for cls in extractor_registry.registered(backend)}
            assert {"ip", "tcp", "udp", "http", "dns"} <= layers
        assert "tls" in {cls.layer for cls in extractor_registry.registered(Backend.PYSHARK)}

    def test_registering_a_new_extractor_needs_no_core_changes(self):
        registry = ExtractorRegistry()  # isolated registry (no package discovery)

        @registry.register(Backend.SCAPY)
        class IcmpExtractor(LayerExtractor[Any]):
            layer = "icmp"

            def applies_to(self, packet):
                return True

            def extract(self, packet):
                return {"type": 8}

        created = registry.create_all(Backend.SCAPY, ParserOptions())
        assert [e.layer for e in created] == ["icmp"]
        assert registry.create_all(Backend.PYSHARK, ParserOptions()) == []

    def test_double_registration_is_ignored(self):
        registry = ExtractorRegistry()

        class X(LayerExtractor[Any]):
            layer = "x"
            def applies_to(self, p): return True
            def extract(self, p): return {}

        registry.register(Backend.SCAPY)(X)
        registry.register(Backend.SCAPY)(X)
        assert registry.registered(Backend.SCAPY) == (X,)


class TestAssembler:
    asm = FrameAssembler()

    @pytest.mark.parametrize("stack, expected", [
        (("eth", "ip", "tcp", "http", "data-text-lines"), "http"),  # Wireshark's top layer for HTML
        (("eth", "ip", "tcp"), "tcp"),
        (("eth", "ip", "udp", "dns"), "dns"),
        (("eth", "ip", "tcp", "data"), "tcp"),
        (("data",), "data"),
        ((), "unknown"),
    ])
    def test_highest_protocol_skips_payload_formats(self, stack, expected):
        assert self.asm.highest_protocol(stack) == expected

    def test_tcp_frame(self):
        frame = self.asm.assemble(
            number=4, timestamp=1.0, length=120, protocols=("eth", "ip", "tcp", "http"),
            layers={"ip": {"src": "10.0.0.2", "dst": "1.2.3.4"},
                    "tcp": {"srcport": 50000, "dstport": "80", "stream": "3"}})
        assert frame.src == Endpoint("10.0.0.2", 50000)
        assert frame.dst == Endpoint("1.2.3.4", 80)  # string port coerced to int
        assert (frame.transport, frame.stream_id) == (Transport.TCP, 3)

    def test_non_ip_frame_has_no_endpoints(self):
        frame = self.asm.assemble(number=1, timestamp=0.0, length=42, protocols=("eth", "arp"), layers={})
        assert frame.src is None and frame.transport is None and frame.highest_protocol == "arp"

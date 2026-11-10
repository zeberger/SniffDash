"""Unit tests for the encrypted-flow rules, the analyzer on hand-made frames, and the
Scapy TCP payload-length fix (Ethernet padding must not count as data)."""

from __future__ import annotations

import pytest

from sniffdash.analysis.analyzers.encrypted import EncryptedFlowAnalyzer, classify
from sniffdash.analysis.base import AnalysisContext
from sniffdash.domain.models import Endpoint, Frame, Transport
from sniffdash.parsing.extractors.tcp_udp import ScapyTcpExtractor
from sniffdash.parsing.options import ParserOptions
from sniffdash.repository import InMemoryFrameRepository

CLIENT, SERVER = Endpoint("10.0.0.2", 51000), Endpoint("1.2.3.4", 443)


def features(**overrides):
    base = dict(duration=1.0, bytes_down=1_000, bytes_up=500, burst_count=1,
                max_burst_bytes=1_000, largest_burst_share=1.0, burst_interval_cv=None)
    return base | overrides


class TestRules:
    def test_video_streaming(self):
        label, reasons = classify(features(duration=30, bytes_down=5_000_000, bytes_up=20_000,
                                           burst_count=8, burst_interval_cv=0.1, largest_burst_share=0.15))
        assert label == "video_streaming" and len(reasons) == 4

    def test_irregular_bursts_are_not_video(self):
        # Same volume, but bursts at random times: not the periodic chunk-fetching of a player.
        label, _ = classify(features(duration=30, bytes_down=5_000_000, bytes_up=20_000,
                                     burst_count=8, burst_interval_cv=1.4, largest_burst_share=0.15))
        assert label != "video_streaming"

    def test_download(self):
        assert classify(features(bytes_down=400_000, largest_burst_share=0.95))[0] == "file_or_image_download"

    def test_polling(self):
        label, _ = classify(features(burst_count=10, max_burst_bytes=900, burst_interval_cv=0.05,
                                     largest_burst_share=0.1))
        assert label == "api_polling"

    def test_fallback_is_explained(self):
        label, reasons = classify(features())
        assert label == "interactive_or_mixed" and reasons


def frame(n, ts, src, dst, payload, protocols=("eth", "ip", "tcp"), stream=0, flags="PA"):
    return Frame(number=n, timestamp=ts, length=54 + payload, protocols=protocols,
                 highest_protocol=protocols[-1], src=src, dst=dst, transport=Transport.TCP,
                 stream_id=stream, layers={"tcp": {"payload_len": payload, "flags": flags}})


class TestAnalyzer:
    def analyze(self, frames):
        return EncryptedFlowAnalyzer().analyze(InMemoryFrameRepository(frames), AnalysisContext())

    def test_non_https_streams_are_ignored(self):
        web = Endpoint("1.2.3.4", 80)
        assert self.analyze([frame(1, 0.0, CLIENT, web, 100), frame(2, 0.1, web, CLIENT, 900)]).flows == ()

    def test_tls_layer_counts_even_on_a_non_standard_port(self):
        odd = Endpoint("1.2.3.4", 9443)
        frames = [frame(1, 0.0, CLIENT, odd, 100, flags="S"),
                  frame(2, 0.1, odd, CLIENT, 900, protocols=("eth", "ip", "tcp", "tls"))]
        flow, = self.analyze(frames).flows
        assert flow.client == CLIENT and flow.server == odd       # SYN sender is the client

    def test_features_and_bursts(self):
        frames = [frame(1, 0.0, CLIENT, SERVER, 100), frame(2, 0.01, SERVER, CLIENT, 1000),
                  frame(3, 0.02, SERVER, CLIENT, 500),
                  frame(4, 2.0, CLIENT, SERVER, 100), frame(5, 2.01, SERVER, CLIENT, 1000)]  # 2 s idle → 2nd burst
        flow, = self.analyze(frames).flows
        assert (flow.bytes_up, flow.bytes_down) == (200, 2500)
        assert (flow.packets_up, flow.packets_down) == (2, 3)
        assert flow.burst_count == 2 and flow.burst_interval_cv is None   # < 3 bursts: regularity unknown
        assert flow.down_size_max == 1000 and flow.largest_burst_share == pytest.approx(0.6)
        assert (flow.first_frame, flow.last_frame) == (1, 5)

    def test_handshake_only_flow_is_skipped(self):
        assert self.analyze([frame(1, 0.0, CLIENT, SERVER, 0, flags="S")]).flows == ()


def test_scapy_payload_length_ignores_ethernet_padding():
    # A bare ACK padded to the 60-byte Ethernet minimum: 0 data bytes, not 6.
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Padding

    wire = bytes(Ether() / IP(src="10.0.0.2", dst="1.2.3.4") / TCP(flags="A") / Padding(b"\x00" * 6))
    packet = Ether(wire)
    assert len(wire) == 60
    assert ScapyTcpExtractor(ParserOptions()).extract(packet)["payload_len"] == 0

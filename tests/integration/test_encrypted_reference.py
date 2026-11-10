"""Integration: encrypted-flow metadata analysis on a synthetic HTTPS capture (AC8).

The capture (``build_https_flows`` in conftest) holds three TLS connections whose
traffic shapes are known: video-like periodic chunks, one image download, and
regular API polling. Both parsers must find all three and label them correctly,
from metadata alone (the payload is opaque TLS application data).

Byte arithmetic: every TLS record adds a 5-byte header on the wire, and content is
sent in 1395-byte record bodies, so N content bytes cost N + 5 * ceil(N / 1395) bytes.
The ClientHello at connection start forms its own (first) burst.
"""

from __future__ import annotations

import math

import pytest

from conftest import analyze_file, backend_params
from sniffdash.domain.results import EncryptedFlowsResult


def wire_bytes(content: int, body: int = 1395) -> int:
    return content + 5 * math.ceil(content / body)


@pytest.fixture(scope="module", params=backend_params())
def flows(request, https_pcap):
    # Module scope: parse the ~1,500-packet capture once per parser, not once per test.
    report, _ = analyze_file(request.param, https_pcap)
    return {f.stream_id: f for f in report.get(EncryptedFlowsResult).flows}


def test_three_flows_labelled_by_shape(flows):
    assert {sid: f.label for sid, f in flows.items()} == {
        0: "video_streaming", 1: "file_or_image_download", 2: "api_polling",
    }


def test_video_flow_features(flows):
    video = flows[0]
    assert video.server.port == 443 and video.client.port == 51000
    assert video.bytes_down == 5 * wire_bytes(250_000)
    assert video.burst_count == 6                       # ClientHello + 5 video chunks
    assert video.burst_interval_cv <= 0.5               # chunks arrive every 3 s
    assert video.down_size_max == 1400                  # one full 1400-byte TLS record per segment
    assert any("regular intervals" in r for r in video.reasons)


def test_download_and_polling_features(flows):
    image, api = flows[1], flows[2]
    assert image.bytes_down == wire_bytes(300_000) and image.largest_burst_share == pytest.approx(1.0)
    assert api.bytes_down == 6 * (800 + 5)
    assert api.burst_count == 7                         # ClientHello + 6 polls


def test_flows_are_citable(flows):
    # First/last frames exist and bracket the flow, so the AI can cite them as evidence.
    for flow in flows.values():
        assert flow.first_frame < flow.last_frame and flow.start_ts < flow.end_ts


def test_sni_is_known_when_the_parser_can_read_tls(request, flows):
    if "pyshark" in request.node.callspec.id:
        assert flows[0].sni == "video.example.com"
    else:
        assert flows[0].sni is None  # Scapy fallback: no TLS dissector (documented)

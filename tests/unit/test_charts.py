"""Unit tests for the Plotly figure builders (Req 26): data, axes, single-series rules, empty states."""

from __future__ import annotations

import pandas as pd
import pytest

from sniffdash.application import load_capture
from sniffdash.demo import build_http_scenario, write_pcap
from sniffdash.parsing.extractors.base import Backend
from sniffdash.ui import charts


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    data = write_pcap(tmp_path_factory.mktemp("c") / "h.pcap", build_http_scenario()).read_bytes()
    return load_capture(data, "demo_http.pcap", backend=Backend.SCAPY)


@pytest.mark.parametrize("metric, unit", [("packets", "packets/s"), ("bytes", "B/s")])
def test_traffic_over_time(session, metric, unit):
    fig = charts.traffic_over_time(session.timeline_frame(), metric)
    trace, = fig.data                                     # one series, one axis
    assert trace.type == "scatter" and trace.line.width == 2
    assert fig.layout.yaxis.title.text == unit and fig.layout.showlegend is False
    assert len(trace.x) == len(session.timeline_frame())


def test_protocol_breakdown(session):
    fig = charts.protocol_breakdown(session.protocol_frame())
    bar, = fig.data
    assert bar.orientation == "h" and sum(bar.x) == 13 and "HTTP" in list(bar.y)
    assert fig.layout.yaxis.autorange == "reversed"       # largest bar on top


def test_top_talkers(session):
    bar, = charts.top_talkers(session.talkers_frame("source"), "Top sources").data
    assert list(bar.y)[0] == "10.0.0.2" and list(bar.x)[0] == 8


def test_dark_mode_uses_its_own_step(session):
    light = charts.protocol_breakdown(session.protocol_frame(), "light").data[0].marker.color
    dark = charts.protocol_breakdown(session.protocol_frame(), "dark").data[0].marker.color
    assert light != dark


@pytest.mark.parametrize("builder", [
    lambda: charts.traffic_over_time(pd.DataFrame(columns=["rel_s", "packets_per_s", "time"])),
    lambda: charts.protocol_breakdown(pd.DataFrame(columns=["protocol", "packets"])),
    lambda: charts.top_talkers(pd.DataFrame(columns=["ip", "packets"]), "x"),
])
def test_empty_states(builder):
    fig = builder()
    assert fig.data == () and fig.layout.annotations[0].text     # a message, not a broken chart

"""Unit tests for the Plotly figure builders (Req 26): data, axes, single-series rules, empty states,
and the walkthrough rules (plan R1.1): descriptive axes, no clipped labels, no view outside the data."""

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


def timeline(session, metric="packets"):
    return charts.traffic_over_time(session.timeline_frame(), metric, interval_s=session.bucket_seconds,
                                    duration_s=session.summary.duration_s)


def all_figures(session):
    return [timeline(session), timeline(session, "bytes"),
            charts.protocol_breakdown(session.protocol_frame()),
            charts.top_talkers(session.talkers_frame("source"), "Top sources")]


@pytest.mark.parametrize("metric, what", [("packets", "Packets"), ("bytes", "Bytes")])
def test_traffic_over_time_counts_per_interval(session, metric, what):
    fig = timeline(session, metric)
    trace, = fig.data                                     # one series, one axis
    assert trace.type == "scatter" and trace.line.width == 2 and fig.layout.showlegend is False
    assert list(trace.y) == list(session.timeline_frame()[metric])   # counts, not per-second rates
    assert fig.layout.title.text == f"{what} per 10 ms interval"     # the 0.5 s demo uses 10 ms intervals
    assert fig.layout.yaxis.title.text == f"{what} in interval"
    assert fig.layout.xaxis.title.text == "Time since capture start (seconds)"


@pytest.mark.parametrize("seconds, label", [(0.01, "10 ms"), (0.5, "500 ms"), (1, "1 s"), (30, "30 s"), (120, "2 min")])
def test_interval_label(seconds, label):
    assert charts.interval_label(seconds) == label


def test_every_axis_has_a_descriptive_title(session):
    for fig in all_figures(session):
        for axis in (fig.layout.xaxis, fig.layout.yaxis):
            title = axis.title.text or ""
            assert len(title.split()) >= 2, f"{fig.layout.title.text!r}: axis title {title!r} is not descriptive"


def test_labels_get_their_own_space(session):
    """Fixed tiny margins cut 'TCP' down to 'P'; automargin sizes the margin to the labels."""
    for fig in all_figures(session):
        assert fig.layout.xaxis.automargin is True and fig.layout.yaxis.automargin is True


def test_bar_values_have_headroom(session):
    fig = charts.top_talkers(session.talkers_frame("source"), "Top sources")
    assert fig.layout.xaxis.range[1] > max(fig.data[0].x) * 1.1   # the printed value fits beside the bar


def test_time_axis_is_bounded_to_the_capture(session):
    fig = timeline(session)
    x = fig.layout.xaxis
    end = session.summary.duration_s
    assert (x.minallowed, x.maxallowed) == (0.0, end) and tuple(x.range) == (0.0, end)
    assert x.fixedrange is False and fig.layout.yaxis.fixedrange is True
    assert fig.layout.dragmode == "pan"                   # dragging moves the view; no zoom box
    config = charts.plot_config(fig)
    assert "zoom2d" in config["modeBarButtonsToRemove"] and "zoomIn2d" not in config["modeBarButtonsToRemove"]


def test_bar_charts_do_not_move(session):
    for fig in all_figures(session)[2:]:
        assert fig.layout.xaxis.fixedrange is True and fig.layout.yaxis.fixedrange is True
        assert fig.layout.dragmode is False
        assert {"pan2d", "zoomIn2d"} <= set(charts.plot_config(fig)["modeBarButtonsToRemove"])


def test_protocol_breakdown(session):
    fig = charts.protocol_breakdown(session.protocol_frame())
    bar, = fig.data
    assert bar.orientation == "h" and sum(bar.x) == 13 and "HTTP" in list(bar.y)
    assert fig.layout.yaxis.autorange == "reversed"       # largest bar on top
    assert "of all packets" in bar.hovertemplate


def test_top_talkers(session):
    fig = charts.top_talkers(session.talkers_frame("source"), "Top sources", category_name="Source IP address")
    bar, = fig.data
    assert list(bar.y)[0] == "10.0.0.2" and list(bar.x)[0] == 8
    assert fig.layout.yaxis.title.text == "Source IP address"


def test_dark_mode_uses_its_own_step(session):
    light = charts.protocol_breakdown(session.protocol_frame(), "light").data[0].marker.color
    dark = charts.protocol_breakdown(session.protocol_frame(), "dark").data[0].marker.color
    assert light != dark


@pytest.mark.parametrize("builder", [
    lambda: charts.traffic_over_time(pd.DataFrame(columns=["rel_s", "packets", "time"])),
    lambda: charts.protocol_breakdown(pd.DataFrame(columns=["protocol", "packets", "share"])),
    lambda: charts.top_talkers(pd.DataFrame(columns=["ip", "packets"]), "x"),
])
def test_empty_states(builder):
    fig = builder()
    assert fig.data == () and fig.layout.annotations[0].text     # a message, not a broken chart

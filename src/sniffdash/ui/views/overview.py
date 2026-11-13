"""Overview tab (Reqs 24–26): headline numbers, traffic over time, protocols, top talkers."""

from __future__ import annotations

import streamlit as st

from sniffdash.ui import charts, labels
from sniffdash.ui.cache import frame_cached
from sniffdash.ui.registry import ResultView, ViewContext, register_view


def _plot(fig) -> None:
    st.plotly_chart(fig, width="stretch", theme=None, config=charts.plot_config(fig))


@register_view
class OverviewView(ResultView):
    title = "Overview"
    order = 10

    def render(self, ctx: ViewContext) -> None:
        session, s = ctx.session, ctx.session.summary
        fp = session.fingerprint

        packets, duration, volume, start = st.columns(4)
        packets.metric("Packets", f"{s.packet_count:,}")
        duration.metric("Duration", f"{s.duration_s:,.3f} s")
        volume.metric("Data", f"{s.total_bytes:,} B")
        start.metric("Start (UTC)", s.start.strftime("%H:%M:%S.%f")[:-3] if s.start else "—")
        if s.start and s.end:
            st.caption(f"First packet {s.start:%Y-%m-%d %H:%M:%S.%f}"[:-3] +
                       f" UTC · last packet {s.end:%Y-%m-%d %H:%M:%S.%f}"[:-3] + " UTC")

        metric = st.segmented_control("Traffic measure", ["packets", "bytes"], default="packets",
                                      key=f"traffic_metric_{fp}") or "packets"
        timeline = frame_cached(session, fp, "timeline")
        _plot(charts.traffic_over_time(timeline, metric, ctx.mode,
                                       interval_s=session.bucket_seconds, duration_s=s.duration_s))
        st.caption("Drag to move along the time axis; scroll or use the + / − buttons to zoom. "
                   "The view stops at the first and last packet.")

        left, right = st.columns(2)
        with left:
            protocols = frame_cached(session, fp, "protocols")
            _plot(charts.protocol_breakdown(protocols, ctx.mode))
            st.caption("Each packet is counted once, under its highest protocol layer, "
                       "so HTTP packets are not also counted as TCP.")
        with right:
            direction = st.segmented_control("Top talkers by", ["source", "destination"], default="source",
                                             key=f"talkers_{fp}") or "source"
            talkers = frame_cached(session, fp, "sources" if direction == "source" else "destinations")
            _plot(charts.top_talkers(talkers, f"Top {direction} IP addresses", ctx.mode,
                                     category_name=f"{direction.capitalize()} IP address"))

        with st.expander("Table view"):  # accessibility: every chart's numbers as a table
            st.dataframe(protocols, hide_index=True, width="stretch", column_config=labels.PROTOCOLS)
            st.dataframe(talkers, hide_index=True, width="stretch", column_config=labels.talkers(direction))
            st.dataframe(timeline, hide_index=True, width="stretch", column_config=labels.TIMELINE)

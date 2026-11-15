"""Encrypted tab: HTTPS/TLS flows characterized from metadata only (Phase 3 creativity feature)."""

from __future__ import annotations

import streamlit as st

from sniffdash.application import AnalysisSession
from sniffdash.ui import labels
from sniffdash.ui.cache import frame_cached
from sniffdash.ui.registry import ResultView, ViewContext, register_view

LABELS = {
    "video_streaming": "Video streaming (likely)",
    "file_or_image_download": "File / image download (likely)",
    "api_polling": "API polling (likely)",
    "interactive_or_mixed": "Interactive / mixed",
}


@register_view
class EncryptedView(ResultView):
    title = "Encrypted"
    order = 30

    def applies(self, session: AnalysisSession) -> bool:  # Audit A6: hidden when there's nothing to show
        return bool(session.encrypted and session.encrypted.flows)

    def render(self, ctx: ViewContext) -> None:
        session = ctx.session
        st.caption("The content of these connections is encrypted. The traffic type is **inferred** from "
                   "packet sizes and timing, so treat it as an informed guess and check the reasons.")
        df = frame_cached(session, session.fingerprint, "encrypted").copy()
        df["inferred_type"] = df["inferred_type"].map(LABELS).fillna(df["inferred_type"])
        st.dataframe(df.drop(columns=["reasons"]), hide_index=True, width="stretch",
                     column_config=labels.ENCRYPTED)

        flow_ids = [f.stream_id for f in session.encrypted.flows]
        chosen = st.selectbox("Explain flow", flow_ids, format_func=lambda sid: f"TCP stream {sid}",
                              key=f"flow_pick_{session.fingerprint}")
        flow = session.encrypted.find(chosen)
        st.markdown(f"**{LABELS.get(flow.label, flow.label)}**: {flow.client} → {flow.server}"
                    + (f" (`{flow.sni}`)" if flow.sni else ""))
        st.markdown("\n".join(f"- {reason}" for reason in flow.reasons))
        a, b, c, d = st.columns(4)
        a.metric("Data bursts", flow.burst_count,
                 help="Groups of packets sent close together, separated by pauses.")
        b.metric("Download ÷ upload", "∞" if flow.bytes_up == 0 else f"{flow.down_up_ratio:,.0f}×",
                 help="Bytes server → client divided by bytes client → server.")
        c.metric("Median time between packets", f"{flow.iat_median * 1000:,.1f} ms",
                 help="Half of the gaps between consecutive data packets are shorter than this.")
        d.metric("Largest burst's share", f"{flow.largest_burst_share:.0%}",
                 help="Fraction of the downloaded bytes carried by the single largest burst.")
        st.caption(f"Evidence: frames {flow.first_frame}–{flow.last_frame}")

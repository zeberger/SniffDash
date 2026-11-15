"""HTTP tab (Reqs 27–29): transactions table; click a row → Follow-HTTP-Stream inspector."""

from __future__ import annotations

import streamlit as st

from sniffdash.application import AnalysisSession
from sniffdash.ui import labels
from sniffdash.ui.cache import frame_cached
from sniffdash.ui.registry import ResultView, ViewContext, register_view


def render_stream(session: AnalysisSession, tx_id: str) -> None:
    view = session.stream(tx_id)
    if view is None:
        st.warning(f"Transaction {tx_id} not found.")
        return
    tx = view.transaction
    timing = f" · response time **{tx.response_time_ms:.1f} ms**" if tx.is_complete else " · **no response captured**"
    st.markdown(f"**{tx.id}** · TCP stream {tx.request.stream_id} · "
                f"frames {', '.join(map(str, view.frame_numbers))}{timing}")
    request, response = st.columns(2)
    with request:
        st.caption(f"Request · frame {tx.request.frame_number} · {tx.request.src} → {tx.request.dst}")
        st.code(view.request_text, language="http", wrap_lines=True)
    with response:
        if tx.response:
            st.caption(f"Response · frame {tx.response.frame_number} · {tx.response.src} → {tx.response.dst}")
        else:
            st.caption("Response")
        st.code(view.response_text, language="http", wrap_lines=True)


@register_view
class HttpView(ResultView):
    title = "HTTP"
    order = 20

    def render(self, ctx: ViewContext) -> None:
        session = ctx.session
        df = frame_cached(session, session.fingerprint, "transactions")
        if df.empty:
            st.info("No HTTP transactions in this capture. (Encrypted HTTPS traffic appears in the "
                    "**Encrypted** tab when present.)")
            return

        http = session.http
        answered = int(df["status"].notna().sum())
        st.caption(f"{len(df)} transactions · {answered} answered · {len(df) - answered} unanswered"
                   + (f" · {len(http.orphan_responses)} responses without a captured request"
                      if http and http.orphan_responses else "")
                   + " · click a row to inspect its stream")

        event = st.dataframe(df, hide_index=True, width="stretch", column_config=labels.TRANSACTIONS,
                             on_select="rerun", selection_mode="single-row", key=f"http_table_{session.fingerprint}")
        rows = event.selection.rows if event and hasattr(event, "selection") else []

        ids = list(df["id"])
        captions = {r.id: f"{r.id} · {r.method} {r.host}{r.uri} · "
                        f"{'no response' if r.reason == 'no response' else int(r.status)}"
                  for r in df.itertuples()}
        # Keyboard-accessible fallback that follows the table selection.
        chosen = st.selectbox("Inspect transaction", ids, index=rows[0] if rows else 0,
                              format_func=captions.get, key=f"http_pick_{session.fingerprint}_{rows[0] if rows else 'n'}")
        st.divider()
        render_stream(session, chosen)

"""Issues tab: everything the parser and analyzers reported (Notification pattern made visible)."""

from __future__ import annotations

import streamlit as st

from sniffdash.ui import labels
from sniffdash.ui.cache import frame_cached
from sniffdash.ui.registry import ResultView, ViewContext, register_view


@register_view
class IssuesView(ResultView):
    title = "Issues"
    order = 90

    def render(self, ctx: ViewContext) -> None:
        df = frame_cached(ctx.session, ctx.session.fingerprint, "issues")
        if df.empty:
            st.success("No parse or analysis issues. Every packet was decoded.")
            return
        counts = df["severity"].value_counts()
        st.caption(" · ".join(f"{n} {sev}" for sev, n in counts.items())
                   + " · warnings affect single packets; errors affect the whole capture")
        st.dataframe(df, hide_index=True, width="stretch", column_config=labels.ISSUES)

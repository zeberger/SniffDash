"""Streamlit caching: parse once, never on a rerun.

Streamlit re-executes the whole script on every click. Without caching, switching a
tab would re-parse the capture. Two caches, chosen per kind of object:

* ``st.cache_resource``: the parsed and analyzed capture (and the app services).
  It is SHARED, not copied. That is safe because every Phase 1–3 object is
  immutable, and it avoids re-pickling a large repository on each rerun.
  ``max_entries=2`` keeps the current capture plus one to switch back to, which
  bounds memory. A load that raises is never cached, so a fixed file can be retried.
* ``st.cache_data``: the derived DataFrames. They are small and handed out as fresh
  copies, so a widget can never corrupt the cached original. They are keyed by the
  capture fingerprint; the session argument itself is excluded from hashing (``_session``).
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from sniffdash.application import AnalysisSession, AppServices, build_services, load_capture
from sniffdash.parsing.extractors.base import Backend


@st.cache_resource(show_spinner=False)
def services_cached() -> AppServices:
    return build_services()


@st.cache_resource(max_entries=2, show_spinner=False)
def load_capture_cached(data: bytes, name: str, backend: str | None, max_packets: int | None) -> AnalysisSession:
    return load_capture(data, name, backend=Backend(backend) if backend else None, max_packets=max_packets)


@st.cache_data(max_entries=32, show_spinner=False)
def frame_cached(_session: AnalysisSession, fingerprint: str, kind: str) -> pd.DataFrame:
    """kind: timeline | protocols | sources | destinations | transactions | encrypted | issues."""
    builders = {
        "timeline": _session.timeline_frame,
        "protocols": _session.protocol_frame,
        "sources": lambda: _session.talkers_frame("source"),
        "destinations": lambda: _session.talkers_frame("destination"),
        "transactions": _session.transactions_frame,
        "encrypted": _session.encrypted_frame,
        "issues": _session.issues_frame,
    }
    return builders[kind]()


def clear_all() -> None:
    """Used by tests (and a sidebar button) to start from a clean slate."""
    st.cache_resource.clear()
    st.cache_data.clear()

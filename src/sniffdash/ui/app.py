"""SniffDash dashboard entry point: sidebar input, cached loading, registry-built tabs.

Error boundaries at two levels:
* **loading:** a bad file, a missing parser, or an analysis failure shows a clear
  message, and nothing is cached, so the user can fix the input and retry;
* **per tab:** one view failing shows its error inside that tab, and the other tabs keep working.
"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from sniffdash.application import DEFAULT_MAX_PACKETS, AnalysisSession, AppServices
from sniffdash.domain.errors import CaptureError, SniffDashError
from sniffdash.ui.cache import clear_all, load_capture_cached, services_cached
from sniffdash.ui.registry import ViewContext, view_registry

CAPTURE_TYPES = ["pcap", "pcapng", "cap"]
BACKEND_CHOICES = ["auto", "pyshark", "scapy"]


def capture_dir() -> Path:
    return Path(os.environ.get("SNIFFDASH_CAPTURE_DIR", "captures"))


def theme_mode() -> str:
    theme = getattr(getattr(st, "context", None), "theme", None)
    return "dark" if getattr(theme, "type", None) == "dark" else "light"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n} B"


def sidebar(services: AppServices) -> tuple[bytes, str, str | None, int] | None:
    """Returns (bytes, name, backend or None, max_packets) for the selected capture, or None."""
    with st.sidebar:
        st.header("Capture")
        uploaded = st.file_uploader("Upload a capture", type=CAPTURE_TYPES,
                                    help="Wireshark .pcap / .pcapng files. Read locally; never uploaded elsewhere.")
        folder = capture_dir()
        local = sorted(p for p in folder.glob("*") if p.suffix.lstrip(".").lower() in CAPTURE_TYPES) \
            if folder.is_dir() else []
        picked = st.selectbox(f"…or open from `{folder}/`", ["—"] + [p.name for p in local],
                              disabled=uploaded is not None,
                              help="Tip: `python -m sniffdash.demo captures` writes two demo captures here.")

        st.header("Parsing")
        available = {b.value for b in services.available_backends}
        backend = st.selectbox(
            "Parser", BACKEND_CHOICES,
            format_func=lambda b: b if b == "auto" or b in available else f"{b} (not installed)",
            help="auto = PyShark (Wireshark's dissectors) when tshark is installed, otherwise Scapy.")
        max_packets = int(st.number_input(
            "Max packets", min_value=1_000, max_value=5_000_000, value=DEFAULT_MAX_PACKETS, step=50_000,
            help="Protects memory on very large files. Results beyond this limit are marked as partial."))
        if st.button("Clear cache", help="Forget loaded captures and re-parse on next load."):
            clear_all()

    if uploaded is not None:
        return uploaded.getvalue(), uploaded.name, None if backend == "auto" else backend, max_packets
    if picked != "—":
        path = folder / picked
        return path.read_bytes(), path.name, None if backend == "auto" else backend, max_packets
    return None


def welcome() -> None:
    st.info("Upload a capture in the sidebar, or pick one from the captures folder, to begin.")
    st.markdown(
        "**No capture at hand?** Generate two demo files:\n\n"
        "```\npython -m sniffdash.demo captures\n```\n"
        "then pick **demo_http.pcap** (HTTP transactions) or **demo_https.pcap** (encrypted flows).")


def header(session: AnalysisSession) -> None:
    s = session.summary
    st.caption(f"**{session.name}** · parsed with {session.parser_name} · "
               f"{s.packet_count:,} packets · {human_bytes(s.total_bytes)}")
    if session.partial:  # Audit A1: visible above every tab
        st.warning("**Partial results.** The file was truncated or cut at the packet limit, so every number "
                   "below describes the loaded portion only. Raise *Max packets* in the sidebar to load more.")


def load(source: tuple[bytes, str, str | None, int]) -> AnalysisSession | None:
    data, name, backend, max_packets = source
    try:
        with st.spinner(f"Parsing and analyzing {name}…"):
            return load_capture_cached(data, name, backend, max_packets)
    except CaptureError as exc:
        st.error(f"**Could not load {name}.** {exc}")
    except SniffDashError as exc:
        st.error(f"**Analysis failed for {name}.** {exc}")
    except Exception as exc:  # last-resort boundary: never a raw traceback for the user
        st.error(f"**Unexpected error while loading {name}.** Please report this: {type(exc).__name__}: {exc}")
    return None


def main() -> None:
    st.set_page_config(page_title="SniffDash", page_icon=":material/lan:", layout="wide")
    services = services_cached()
    st.title("SniffDash")
    st.caption("Network traffic analysis for .pcap / .pcapng captures, with AI answers backed by frame-level evidence.")

    source = sidebar(services)
    if source is None:
        welcome()
        return
    session = load(source)
    if session is None:
        return

    header(session)
    ctx = ViewContext(session=session, services=services, mode=theme_mode())
    views = [v for v in view_registry.create_all() if v.applies(session)]
    for tab, view in zip(st.tabs([v.title for v in views]), views):
        with tab:
            try:
                view.render(ctx)
            except Exception as exc:  # per-tab boundary: other tabs keep working
                st.error(f"This view could not be displayed: {type(exc).__name__}: {exc}. "
                         "The other tabs are unaffected.")

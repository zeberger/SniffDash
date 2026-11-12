"""Small helpers shared by the AppTest modules."""

from __future__ import annotations

from streamlit.testing.v1 import AppTest


def open_capture(at: AppTest, name: str) -> AppTest:
    picker = next(s for s in at.selectbox if s.label.startswith("…or open from"))
    return picker.select(name).run()


def tab_labels(at: AppTest) -> list[str]:
    return [t.label for t in at.tabs]


def texts(elements) -> str:
    return "\n".join(str(e.value) for e in elements)

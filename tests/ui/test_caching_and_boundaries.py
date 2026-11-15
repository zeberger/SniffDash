"""Guarantees that must hold for the dashboard to stay fast and robust (AC7, AC8, A3).

* Parse once: reruns (widget clicks, questions) never call the parser again.
* Failed loads are NOT cached: fixing the input and retrying works.
* A crashing tab is contained: the other tabs still render (per-tab error boundary),
  and a new tab plugs in without touching the layout (Open/Closed).
"""

from __future__ import annotations

from llm_doubles import ScriptedClient, call
from sniffdash.llm.service import LLMService
from sniffdash.ui import cache
from sniffdash.ui.registry import ResultView, ViewRegistry, view_registry
from sniffdash.ui.views.chat import SERVICE_OVERRIDE_KEY
from ui_fixtures import app, demo_dir  # noqa: F401  (pytest fixtures)
from ui_helpers import open_capture, tab_labels, texts


def counting(monkeypatch):
    calls = []
    real = cache.load_capture

    def wrapper(*args, **kwargs):
        calls.append(args[1])
        return real(*args, **kwargs)

    monkeypatch.setattr(cache, "load_capture", wrapper)
    return calls


def test_capture_is_parsed_once_across_reruns(app, monkeypatch):
    calls = counting(monkeypatch)
    app.session_state[SERVICE_OVERRIDE_KEY] = LLMService(ScriptedClient(
        call("submit_answer", answer="ok", evidence=[], insufficient_data=True)))
    open_capture(app.run(), "demo_http.pcap")
    next(s for s in app.selectbox if s.label == "Inspect transaction").select("tx-6").run()   # rerun 1
    app.chat_input[0].set_value("anything").run()                                              # rerun 2
    app.run()                                                                                  # rerun 3
    assert calls == ["demo_http.pcap"]


def test_failed_load_is_not_cached(app, monkeypatch):
    calls = counting(monkeypatch)
    open_capture(app.run(), "broken.pcap")
    app.run()
    assert calls == ["broken.pcap", "broken.pcap"]   # retried, because exceptions are never cached
    assert "Could not load" in texts(app.error)


class ExplodingView(ResultView):
    title = "Exploding"
    order = 15

    def render(self, ctx):
        raise RuntimeError("view bug")


def test_crashing_tab_is_contained_and_new_tabs_plug_in(app, monkeypatch):
    registry = ViewRegistry()          # isolated: built-in views + one test-only view
    for view in view_registry.create_all():
        registry.register(type(view))
    registry.register(ExplodingView)
    monkeypatch.setattr("sniffdash.ui.app.view_registry", registry)

    open_capture(app.run(), "demo_http.pcap")
    assert not app.exception
    assert tab_labels(app) == ["Overview", "Exploding", "HTTP", "Ask AI", "Issues"]   # no layout change needed
    assert "This view could not be displayed: RuntimeError: view bug" in texts(app.error)
    assert any(m.label == "Packets" for m in app.metric)                  # other tabs still rendered

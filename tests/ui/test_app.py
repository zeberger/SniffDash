"""Headless dashboard tests (AC1–AC8, AC11, AC12) with Streamlit's AppTest.

AppTest runs the REAL app.py script in-process and lets the test drive its widgets
(pick a capture, type a chat question) and inspect what was rendered.
"""

from __future__ import annotations

from llm_doubles import ScriptedClient, call, last_tool_result
from sniffdash.domain.errors import LLMRateLimitError
from sniffdash.llm.service import LLMService
from sniffdash.ui.views.chat import SERVICE_OVERRIDE_KEY
from ui_fixtures import app, demo_dir  # noqa: F401  (pytest fixtures)
from ui_helpers import open_capture, tab_labels, texts


def test_welcome_without_a_capture(app):
    app.run()
    assert not app.exception
    assert "Upload a capture" in texts(app.info)
    assert "python -m sniffdash.demo captures" in texts(app.markdown)


def test_overview_of_the_http_demo(app):
    open_capture(app.run(), "demo_http.pcap")
    assert not app.exception
    assert tab_labels(app) == ["Overview", "HTTP", "Ask AI", "Issues"]   # no TLS → no Encrypted tab (A6)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Packets"] == "13" and metrics["Duration"] == "0.500 s"
    assert "13 packets" in texts(app.caption)


def test_http_table_and_stream_inspector(app):
    open_capture(app.run(), "demo_http.pcap")
    table = next(df.value for df in app.dataframe if "request_frame" in df.value.columns)
    assert list(table["id"]) == ["tx-4", "tx-6", "tx-13"]
    assert list(table["response_ms"].round(1)[:2]) == [120.0, 60.0]
    code = texts(app.code)
    assert "GET /index.html HTTP/1.1" in code and "<html>hello</html>" in code   # tx-4 inspected by default

    picker = next(s for s in app.selectbox if s.label == "Inspect transaction")
    picker.select("tx-13").run()
    assert "(no response captured)" in texts(app.code) and "POST /api/login" in texts(app.code)


def test_encrypted_tab_on_the_https_demo(app):
    open_capture(app.run(), "demo_https.pcap")
    assert "Encrypted" in tab_labels(app)
    flows = next(df.value for df in app.dataframe if "inferred_type" in df.value.columns)
    assert list(flows["inferred_type"]) == ["Video streaming (likely)", "File / image download (likely)",
                                            "API polling (likely)"]
    assert "regular intervals" in texts(app.markdown)


def test_packet_limit_shows_partial_banner(app):
    # demo_https has ~1,500 packets; a 1,000-packet limit must be flagged above every tab (AC11).
    app.run()
    app.number_input[0].set_value(1000)
    open_capture(app, "demo_https.pcap")
    assert "Partial results" in texts(app.warning)
    assert next(m.value for m in app.metric if m.label == "Packets") == "1,000"


def test_broken_file_shows_a_friendly_error(app):
    open_capture(app.run(), "broken.pcap")
    assert not app.exception                                   # no traceback for the user
    assert "Could not load broken.pcap" in texts(app.error)


def test_no_key_shows_setup_instructions(app):
    open_capture(app.run(), "demo_http.pcap")
    assert "AI answers are not available" in texts(app.warning)
    assert "aistudio.google.com" in texts(app.markdown)


def cite_slowest(turns):
    top = last_tool_result(turns, "slowest_http_requests")["slowest"][0]
    return call("submit_answer", answer="tx-4 was slowest (120 ms).", insufficient_data=False, evidence=[
        {"frame_number": top["request_frame"], "timestamp": top["request_time"], "claim": "request"},
        {"frame_number": top["response_frame"], "timestamp": top["response_time"], "claim": "response"}])


def test_ask_ai_renders_verified_evidence(app):
    app.session_state[SERVICE_OVERRIDE_KEY] = LLMService(ScriptedClient(call("slowest_http_requests"), cite_slowest))
    open_capture(app.run(), "demo_http.pcap")
    app.chat_input[0].set_value("Which HTTP request was the slowest?").run()
    assert not app.exception
    assert "tx-4 was slowest (120 ms)." in texts(app.markdown)
    evidence = next(df.value for df in app.dataframe if "claim" in df.value.columns)
    assert list(evidence["frame"]) == [4, 5] and list(evidence["transaction"]) == ["tx-4", "tx-4"]
    assert "each verified against the capture" in texts(app.caption)


class FailingThenWorking:
    """First question hits the quota; the second succeeds."""

    def __init__(self):
        self.calls = 0

    def complete(self, system, turns, tools):
        self.calls += 1
        if self.calls == 1:
            raise LLMRateLimitError("free tier limit")
        return call("submit_answer", answer="No DNS errors.", evidence=[], insufficient_data=True)


def test_failed_question_keeps_history(app):
    # Audit A7: a quota error is shown in-line and never erases the conversation.
    app.session_state[SERVICE_OVERRIDE_KEY] = LLMService(FailingThenWorking())
    open_capture(app.run(), "demo_http.pcap")
    app.chat_input[0].set_value("first").run()
    assert "Quota reached" in texts(app.error)
    app.chat_input[0].set_value("second").run()
    assert "Quota reached" in texts(app.error) and "No DNS errors." in texts(app.markdown)
    assert {"first", "second"} <= {m.value for m in app.markdown}

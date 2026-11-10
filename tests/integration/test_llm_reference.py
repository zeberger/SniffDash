"""End-to-end Q&A on real parsed captures (Reqs 30–34).

Scripted tests: a ScriptedClient behaves like a well-behaved model, calling the right
tool and citing exactly what the tool returned. They prove the whole chain works on
both parsers: parse → analyze → context → tool → submit_answer → citation check.

Live tests (``pytest -m live_llm``, needs GEMINI_API_KEY in .env): the real model
answers the four required questions. They prove the grounding actually works. The
set is kept small because free-tier quotas are tiny.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import ScriptedClient, analyze_file, backend_params, call, last_tool_result
from sniffdash.llm.service import LLMService


@pytest.fixture(scope="module", params=backend_params())
def analyzed(request, http_pcap):
    return analyze_file(request.param, http_pcap)


def cite(rows, answer_text):
    """submit_answer citing request+response frames of the given tool rows."""
    evidence = []
    for row in rows:
        evidence.append({"frame_number": row["request_frame"], "timestamp": row["request_time"], "claim": "request"})
        if row["response_frame"]:
            evidence.append({"frame_number": row["response_frame"], "timestamp": row["response_time"],
                             "claim": "response"})
    return call("submit_answer", answer=answer_text, evidence=evidence, insufficient_data=False)


def run(analyzed, question, *steps):
    report, repo = analyzed
    return LLMService(ScriptedClient(*steps)).ask(question, report, repo)


# --- The four required query types (Req 32) ------------------------------------------

def test_slowest_request(analyzed):
    result = run(analyzed, "Which request was slowest?", call("slowest_http_requests", limit=1),
                 lambda t: cite(last_tool_result(t, "slowest_http_requests")["slowest"], "tx-4: 120 ms"))
    assert result.fully_grounded and [e.frame_number for e in result.valid_evidence] == [4, 5]


def test_count_requests_to_host(analyzed):
    def answer(turns):
        r = last_tool_result(turns, "count_requests_by_host")
        assert r["count"] == 2
        return cite(r["transactions"], f"{r['count']} requests went to example.com")
    result = run(analyzed, "How many requests went to example.com?",
                 call("count_requests_by_host", host="example.com"), answer)
    assert result.fully_grounded and [e.frame_number for e in result.valid_evidence] == [4, 5, 6, 7]


def test_status_codes(analyzed):
    def answer(turns):
        r = last_tool_result(turns, "status_code_summary")
        assert r["counts"] == {"200": 1, "404": 1, "unanswered": 1}
        rows = [row for rows in r["transactions_by_status"].values() for row in rows]
        return cite(rows, "One 200, one 404, and one request with no response.")
    result = run(analyzed, "Which status codes were returned?", call("status_code_summary"), answer)
    assert result.fully_grounded and {e.frame_number for e in result.valid_evidence} == {4, 5, 6, 7, 13}


def test_explain_transaction(analyzed):
    def answer(turns):
        r = last_tool_result(turns, "get_transaction")
        assert "GET /index.html" in r["request_text"]
        return cite([r], "A GET for /index.html answered 200 OK in 120 ms.")
    result = run(analyzed, "Explain transaction tx-4.", call("get_transaction", transaction_id="tx-4"), answer)
    assert result.fully_grounded


def test_encrypted_question(https_pcap):
    from sniffdash.parsing.scapy_parser import ScapyParser
    report, repo = analyze_file(ScapyParser, https_pcap)  # Scapy: always available

    def answer(turns):
        flow = last_tool_result(turns, "encrypted_flows")["flows"][0]
        assert flow["inferred_type"] == "video_streaming"
        return call("submit_answer", answer="Stream 0 is likely video streaming.", insufficient_data=False,
                    evidence=[{"frame_number": flow["first_frame"], "timestamp": flow["first_time"], "claim": "start"},
                              {"frame_number": flow["last_frame"], "timestamp": flow["last_time"], "claim": "end"}])
    result = LLMService(ScriptedClient(call("encrypted_flows"), answer)).ask(
        "What kind of encrypted traffic is this?", report, repo, skill_level="beginner")
    assert result.fully_grounded


# --- Live Gemini (opt-in) -------------------------------------------------------------

LIVE_QUESTIONS = [
    ("expert", "Which HTTP request was the slowest, and how long did it take?", ["120"]),
    ("expert", "How many HTTP requests were sent to example.com?", ["2"]),
    ("expert", "Which HTTP status codes were returned in this capture?", ["200", "404"]),
    ("expert", "Explain HTTP transaction tx-4.", ["index.html"]),
    ("beginner", "Which HTTP request was the slowest?", ["120"]),
]


@pytest.mark.live_llm
@pytest.mark.parametrize("level, question, must_mention", LIVE_QUESTIONS)
def test_live_gemini(http_pcap, level, question, must_mention):
    from sniffdash.config import load_settings
    from sniffdash.llm.client import GeminiClient
    from sniffdash.parsing.scapy_parser import ScapyParser

    settings = load_settings(Path(__file__).resolve().parents[2] / ".env")
    if not settings.gemini_api_key:
        pytest.skip("GEMINI_API_KEY not set in .env")
    report, repo = analyze_file(ScapyParser, http_pcap)
    result = LLMService(GeminiClient(settings)).ask(question, report, repo, skill_level=level)
    print(f"\n[{level}] {question}\n→ {result.answer}\n  evidence: {result.valid_evidence}\n"
          f"  invalid: {result.invalid_citations}\n  tools: {result.tools_used}")
    assert result.invalid_citations == (), result.invalid_citations
    assert result.valid_evidence, "the model gave no evidence"
    for fact in must_mention:
        assert fact in result.answer

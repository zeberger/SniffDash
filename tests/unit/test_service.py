"""Unit tests for LLMService's conversation loop and the skill-aware prompt (AC3, AC5, AC7)."""

from __future__ import annotations

import pytest

from conftest import ScriptedClient, analyze_file, call, last_tool_result
from sniffdash.domain.errors import LLMError, LLMResponseFormatError
from sniffdash.llm.answer import SkillLevel
from sniffdash.llm.client import LLMReply
from sniffdash.llm.prompts import build_system_prompt
from sniffdash.llm.service import LLMService
from sniffdash.parsing.scapy_parser import ScapyParser

RULES_END = "## Explanation style"


@pytest.fixture(scope="module")
def analyzed(http_pcap):
    return analyze_file(ScapyParser, http_pcap)


def ask(client, analyzed, question="Which request was slowest?", **kwargs):
    report, repo = analyzed
    return LLMService(client).ask(question, report, repo, **kwargs)


def submit(answer="ok", evidence=(), insufficient=False):
    return call("submit_answer", answer=answer, evidence=list(evidence), insufficient_data=insufficient)


def cite_slowest(turns):
    """Answer like a good model: copy the frames and timestamps the tool returned."""
    top = last_tool_result(turns, "slowest_http_requests")["slowest"][0]
    return submit(f"{top['transaction_id']} took {top['response_time_ms']} ms (frames 4 and 5).", [
        {"frame_number": top["request_frame"], "timestamp": top["request_time"], "claim": "request"},
        {"frame_number": top["response_frame"], "timestamp": top["response_time"], "claim": "response"},
    ])


def test_tool_then_answer(analyzed):
    client = ScriptedClient(call("slowest_http_requests", limit=1), cite_slowest)
    result = ask(client, analyzed)
    assert result.fully_grounded and [e.frame_number for e in result.valid_evidence] == [4, 5]
    assert result.tools_used == ("slowest_http_requests",)
    first_turn = client.calls[0]["turns"][0].text
    assert first_turn.startswith("CAPTURE CONTEXT (JSON):") and "Which request was slowest?" in first_turn
    assert {t["name"] for t in client.calls[0]["tools"]} >= {"submit_answer", "slowest_http_requests"}


def test_parallel_tool_calls_in_one_round(analyzed):
    both = LLMReply(text=None, tool_calls=(call("count_requests_by_host", host="example.com").tool_calls[0],
                                           call("status_code_summary").tool_calls[0]))
    client = ScriptedClient(both, submit("2 requests", insufficient=False))
    result = ask(client, analyzed)
    assert result.tools_used == ("count_requests_by_host", "status_code_summary")
    tool_turn = client.calls[1]["turns"][-1]
    assert [r.name for r in tool_turn.tool_results] == ["count_requests_by_host", "status_code_summary"]
    assert tool_turn.tool_results[0].content["count"] == 2


def test_invalid_citation_is_flagged_not_hidden(analyzed):
    made_up = submit("Frame 99 shows it.", [{"frame_number": 99, "timestamp": "2023-11-14T22:13:20.000Z",
                                             "claim": "invented"}])
    result = ask(ScriptedClient(made_up), analyzed)
    assert not result.fully_grounded and {i.frame_number for i in result.invalid_citations} == {99}


def test_malformed_answer_gets_one_repair(analyzed):
    client = ScriptedClient(call("submit_answer", answer="", evidence=[], insufficient_data=False),
                            submit("No DNS here.", insufficient=True))
    result = ask(client, analyzed)
    assert result.insufficient_data
    repair_turn = client.calls[1]["turns"][-1].tool_results[0]
    assert repair_turn.name == "submit_answer" and "Invalid answer" in repair_turn.content["error"]


def test_second_malformed_answer_fails(analyzed):
    bad = call("submit_answer", answer="", evidence=[], insufficient_data=False)
    with pytest.raises(LLMResponseFormatError):
        ask(ScriptedClient(bad, bad), analyzed)


def test_text_reply_is_steered_back_to_submit_answer(analyzed):
    client = ScriptedClient(LLMReply(text="Probably tx-4.", tool_calls=()), submit("ok", insufficient=True))
    assert ask(client, analyzed).answer == "ok"
    assert "submit_answer" in client.calls[1]["turns"][-1].text


def test_tool_round_limit(analyzed):
    loop = [call("get_frames", frame_numbers=[1])] * 5
    with pytest.raises(LLMError, match="4 tool rounds"):
        ask(ScriptedClient(*loop), analyzed)


def test_tool_errors_go_back_to_the_model(analyzed):
    client = ScriptedClient(call("get_transaction", transaction_id="tx-999"), submit("none", insufficient=True))
    ask(client, analyzed)
    assert "No HTTP transaction" in client.calls[1]["turns"][-1].tool_results[0].content["error"]


@pytest.mark.parametrize("question", ["", "   "])
def test_empty_question_rejected(analyzed, question):
    with pytest.raises(ValueError):
        ask(ScriptedClient(), analyzed, question=question)


def test_invalid_skill_level_rejected(analyzed):
    with pytest.raises(ValueError, match="skill level"):
        ask(ScriptedClient(), analyzed, skill_level="guru")


# --- Skill levels (AC7) -------------------------------------------------------------

def test_each_level_gets_its_own_style(analyzed):
    for level, marker in [("beginner", "plain, everyday words"), ("intermediate", "networking student"),
                          ("expert", "protocol-level terminology")]:
        client = ScriptedClient(submit("ok", insufficient=True))
        result = ask(client, analyzed, skill_level=level)
        assert result.skill_level == SkillLevel(level) and marker in client.calls[0]["system"]


def test_evidence_rules_are_identical_at_every_level():
    rules = {build_system_prompt(level).split(RULES_END)[0] for level in SkillLevel}
    assert len(rules) == 1                              # byte-identical grounding rules
    assert "{explanation_style}" not in build_system_prompt(SkillLevel.EXPERT)

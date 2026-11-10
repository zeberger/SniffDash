"""Unit tests for the token-budgeted context (AC1), on the real reference capture."""

from __future__ import annotations

import json

import pytest

from conftest import analyze_file
from sniffdash.analysis import AnalysisEngine
from sniffdash.llm.context import ContextBuilder, estimate_tokens
from sniffdash.parsing.scapy_parser import ScapyParser
from sniffdash.repository import InMemoryFrameRepository


@pytest.fixture(scope="module")
def report(http_pcap):
    return analyze_file(ScapyParser, http_pcap)[0]


def test_all_sections_present(report):
    ctx = ContextBuilder().build(report)
    assert set(ctx) >= {"capture", "protocols", "top_sources", "top_destinations",
                        "http_overview", "transaction_index"}
    assert ctx["capture"]["packets"] == 13
    overview = ctx["http_overview"]
    assert (overview["transactions"], overview["answered"], overview["unanswered"]) == (3, 2, 1)
    assert overview["by_status"] == {"200": 1, "404": 1}
    assert overview["by_host"] == {"api.example.com": 1, "example.com": 2}
    assert overview["slowest"][0]["id"] == "tx-4" and overview["slowest"][0]["rt_ms"] == pytest.approx(120.0)


def test_full_index_when_it_fits(report):
    index = ContextBuilder().build(report)["transaction_index"]
    assert [row[0] for row in index["rows"]] == ["tx-4", "tx-6", "tx-13"] and "truncated" not in index


def test_tiny_budget_truncates_only_the_index(report):
    ctx = ContextBuilder(budget_tokens=10).build(report)
    assert ctx["transaction_index"]["truncated"]["omitted"] == 3
    assert ctx["http_overview"]["slowest"]          # the overview is never cut


def test_no_headers_or_bodies(report):
    text = ContextBuilder.render(ContextBuilder().build(report))
    assert "alice" not in text and "User-Agent" not in text   # login body and headers stay out


def test_deterministic_and_serializable(report):
    a = ContextBuilder.render(ContextBuilder().build(report))
    assert a == ContextBuilder.render(ContextBuilder().build(report)) and json.loads(a)


def test_budget_is_respected_when_rows_must_go(report):
    builder = ContextBuilder(budget_tokens=estimate_tokens(ContextBuilder.render(ContextBuilder().build(report))) - 5)
    assert estimate_tokens(ContextBuilder.render(builder.build(report))) <= builder._budget


def test_empty_capture():
    ctx = ContextBuilder().build(AnalysisEngine().run(InMemoryFrameRepository([])))
    assert ctx["capture"]["packets"] == 0 and ctx["transaction_index"]["rows"] == []

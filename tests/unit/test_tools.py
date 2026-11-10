"""Unit tests for the query tools (AC2, AC6), on real parsed captures.

The expected values are the reference scenario's ground truth (tests/conftest.py).
"""

from __future__ import annotations

import json

import pytest

from conftest import analyze_file
from sniffdash.llm.redaction import REDACTED, redact
from sniffdash.llm.tools import ToolBox, ToolContext
from sniffdash.llm.tools.http_tools import normalize_host
from sniffdash.parsing.scapy_parser import ScapyParser

ALLOWED_SCHEMA_KEYS = {"type", "properties", "required", "items", "enum", "description"}


@pytest.fixture(scope="module")
def ctx(http_pcap):
    report, repo = analyze_file(ScapyParser, http_pcap)
    return ToolContext(report, repo)


@pytest.fixture(scope="module")
def https_ctx(https_pcap):
    report, repo = analyze_file(ScapyParser, https_pcap)
    return ToolContext(report, repo)


@pytest.fixture(scope="module")
def box():
    return ToolBox.default()


# --- The four required query types ---------------------------------------------------

def test_slowest_request(box, ctx):
    result = box.run("slowest_http_requests", {"limit": 1}, ctx)
    top, = result["slowest"]
    assert (top["transaction_id"], top["request_frame"], top["response_frame"]) == ("tx-4", 4, 5)
    assert top["response_time_ms"] == pytest.approx(120.0)
    assert top["request_time"] == "2023-11-14T22:13:20.030Z"     # citable, exact format
    assert result["unanswered_not_ranked"] == 1


@pytest.mark.parametrize("host", ["example.com", "EXAMPLE.COM", "http://example.com:80/"])
def test_count_requests_by_host(box, ctx, host):
    result = box.run("count_requests_by_host", {"host": host}, ctx)
    assert result["count"] == 2
    assert [t["transaction_id"] for t in result["transactions"]] == ["tx-4", "tx-6"]


def test_status_code_summary(box, ctx):
    result = box.run("status_code_summary", {}, ctx)
    assert result["counts"] == {"200": 1, "404": 1, "unanswered": 1}
    assert result["transactions_by_status"]["404"][0]["response_frame"] == 7


def test_explain_transaction(box, ctx):
    by_id = box.run("get_transaction", {"transaction_id": "tx-4"}, ctx)
    by_frame = box.run("get_transaction", {"frame_number": 5}, ctx)   # response frame finds it too
    assert by_id == by_frame
    assert by_id["request_text"].startswith("GET /index.html HTTP/1.1")
    assert "<html>hello</html>" in by_id["response_text"] and by_id["stream_frames"] == [4, 5]


def test_unanswered_transaction_detail(box, ctx):
    result = box.run("get_transaction", {"transaction_id": "tx-13"}, ctx)
    assert result["status"] is None and result["response_text"] == "(no response captured)"


# --- Frames & encrypted flows ----------------------------------------------------------

def test_get_frames(box, ctx):
    result = box.run("get_frames", {"frame_numbers": [1, 5, 99]}, ctx)
    assert [f["frame"] for f in result["frames"]] == [1, 5] and result["not_found"] == [99]
    assert result["frames"][0]["tcp_flags"] == "S"


def test_encrypted_flow_tools(box, https_ctx):
    listing = box.run("encrypted_flows", {}, https_ctx)
    assert "INFERENCE" in listing["note"]
    assert [f["inferred_type"] for f in listing["flows"]] == [
        "video_streaming", "file_or_image_download", "api_polling"]          # largest first
    detail = box.run("get_encrypted_flow", {"stream_id": 0}, https_ctx)
    assert detail["reasons"] and detail["inter_arrival_s"]["p95"] >= 0
    assert detail["first_frame"] < detail["last_frame"]


# --- Robustness: errors are returned, never raised -----------------------------------------

@pytest.mark.parametrize("name, args, fragment", [
    ("no_such_tool", {}, "Unknown tool"),
    ("count_requests_by_host", {}, "'host' is required"),
    ("get_transaction", {}, "transaction_id or frame_number"),
    ("get_transaction", {"transaction_id": "tx-999"}, "No HTTP transaction"),
    ("get_frames", {"frame_numbers": list(range(51))}, "At most 50"),
])
def test_errors_are_returned(box, ctx, name, args, fragment):
    assert fragment in box.run(name, args, ctx)["error"]


def test_no_encrypted_flows_is_an_error_not_a_crash(box, ctx):
    assert "no encrypted" in box.run("encrypted_flows", {}, ctx)["error"]


# --- Privacy (AC6) ---------------------------------------------------------------------

def test_redaction_of_headers_and_secret_fields():
    text = ("POST /login HTTP/1.1\r\nCookie: session=abc123\r\nAuthorization: Bearer xyz\r\n\r\n"
            'user=alice&password=hunter2 {"api_key": "K-999"}')
    out = redact(text)
    for secret in ("abc123", "Bearer xyz", "hunter2", "K-999"):
        assert secret not in out
    assert out.count(REDACTED) == 4 and "user=alice" in out


def test_long_bodies_are_truncated():
    assert "truncated: 500 more characters" in redact("x" * 2500)


# --- Declarations stay inside Gemini's schema subset -----------------------------------

def test_declarations_use_only_the_supported_schema_subset(box):
    def keys(schema):
        found = set(schema)
        for sub in schema.get("properties", {}).values():
            found |= keys(sub)
        if "items" in schema:
            found |= keys(schema["items"])
        return found

    declarations = box.declarations()
    assert {d["name"] for d in declarations} == {
        "slowest_http_requests", "count_requests_by_host", "status_code_summary", "get_transaction",
        "get_frames", "encrypted_flows", "get_encrypted_flow"}
    for d in declarations:
        assert keys(d["parameters"]) <= ALLOWED_SCHEMA_KEYS, d["name"]
        assert d["description"] and json.dumps(d)


def test_normalize_host():
    assert normalize_host(" HTTPS://Api.Example.com:8443/v1 ") == "api.example.com"
    assert normalize_host("::1") == "::1"   # IPv6 colons are not a port

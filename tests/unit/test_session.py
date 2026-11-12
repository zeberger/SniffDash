"""Unit tests for the AnalysisSession facade (AC1–AC4, AC11, A2, A4, A10).

The facade is plain Python, so everything the dashboard shows is tested here
without a browser, on the real demo captures.
"""

from __future__ import annotations

import glob
import tempfile

import pytest

from conftest import ScriptedClient, call
from sniffdash.application import build_services, capture_fingerprint, load_capture
from sniffdash.demo import build_http_scenario, build_https_flows, write_pcap
from sniffdash.domain.errors import CorruptCaptureError, UnsupportedFormatError
from sniffdash.llm.service import LLMService
from sniffdash.parsing.extractors.base import Backend


@pytest.fixture(scope="module")
def http_bytes(tmp_path_factory):
    return write_pcap(tmp_path_factory.mktemp("s") / "h.pcap", build_http_scenario()).read_bytes()


@pytest.fixture(scope="module")
def session(http_bytes):
    return load_capture(http_bytes, "demo_http.pcap", backend=Backend.SCAPY)


def test_summary_and_identity(session):
    assert session.name == "demo_http.pcap" and session.parser_name == "scapy"
    assert session.summary.packet_count == 13 and not session.partial


def test_transactions_table_has_every_required_column(session):
    df = session.transactions_frame()
    row = df.iloc[0].to_dict()
    assert (row["id"], row["method"], row["host"], row["uri"], row["status"]) == \
        ("tx-4", "GET", "example.com", "/index.html", 200)
    assert (row["source"], row["destination"]) == ("10.0.0.2:50000", "93.184.216.34:80")
    assert row["response_ms"] == pytest.approx(120.0)
    assert (row["request_frame"], row["response_frame"]) == (4, 5)
    assert row["rel_s"] == pytest.approx(0.030)          # Wireshark-style relative time (A4)
    unanswered = df[df["id"] == "tx-13"].iloc[0]
    assert unanswered["reason"] == "no response" and str(unanswered["status"]) == "<NA>"


def test_overview_tables(session):
    assert session.protocol_frame()["packets"].sum() == 13
    assert session.protocol_frame()["share"].sum() == pytest.approx(1.0)
    assert session.talkers_frame("source").iloc[0].to_dict() == {"ip": "10.0.0.2", "packets": 8}
    timeline = session.timeline_frame()
    assert timeline["packets"].sum() == 13 and timeline["rel_s"].iloc[0] == 0.0


def test_stream_and_lookups(session):
    view = session.stream("tx-4")
    assert "GET /index.html" in view.request_text and view.frame_numbers == (4, 5)
    assert session.stream("tx-999") is None
    assert session.transaction_for_frame(5).id == "tx-4"
    info = session.frame_info(8)                          # a DNS frame: evidence without a transaction (A10)
    assert info["protocols"].endswith("dns") and session.transaction_for_frame(8) is None
    assert session.frame_info(999) is None


def test_https_capture_tables(tmp_path):
    data = write_pcap(tmp_path / "s.pcap", build_https_flows()).read_bytes()
    s = load_capture(data, "demo_https.pcap", backend=Backend.SCAPY)
    assert list(s.encrypted_frame()["inferred_type"]) == ["video_streaming", "file_or_image_download", "api_polling"]
    assert s.transactions_frame().empty                   # no HTTP: empty table, not an error


def test_packet_limit_marks_everything_partial(http_bytes):
    s = load_capture(http_bytes, "big.pcap", backend=Backend.SCAPY, max_packets=5)
    assert s.partial and s.summary.packet_count == 5
    assert any("max_packets" in i.message for i in s.issues)


def test_fingerprint_covers_bytes_parser_and_limit(http_bytes):
    # A2: different parse of the same file ⇒ different chat history.
    base = capture_fingerprint(http_bytes, None, 200_000)
    assert base == capture_fingerprint(http_bytes, None, 200_000)
    assert base != capture_fingerprint(http_bytes, Backend.SCAPY, 200_000)
    assert base != capture_fingerprint(http_bytes, None, 100)
    assert base != capture_fingerprint(http_bytes + b"x", None, 200_000)


@pytest.mark.parametrize("data, error", [(b"", CorruptCaptureError), (b"not a capture at all" * 5, UnsupportedFormatError)])
def test_bad_uploads_raise_typed_errors(data, error):
    with pytest.raises(error):
        load_capture(data, "upload.pcap", backend=Backend.SCAPY)


def test_temporary_upload_copy_is_removed(http_bytes):
    before = set(glob.glob(f"{tempfile.gettempdir()}/sniffdash-*"))
    load_capture(http_bytes, "x.pcapng", backend=Backend.SCAPY)
    with pytest.raises(UnsupportedFormatError):
        load_capture(b"garbage" * 20, "y.pcap", backend=Backend.SCAPY)   # also on failure
    assert set(glob.glob(f"{tempfile.gettempdir()}/sniffdash-*")) == before


def test_ask_delegates_to_the_service(session):
    service = LLMService(ScriptedClient(call("submit_answer", answer="none", evidence=[], insufficient_data=True)))
    assert session.ask("Any DNS?", "beginner", service).insufficient_data


def test_no_key_means_no_llm_with_a_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    services = build_services(tmp_path / "missing.env")
    assert services.llm is None and "GEMINI_API_KEY" in services.llm_unavailable_reason
    assert Backend.SCAPY in services.available_backends

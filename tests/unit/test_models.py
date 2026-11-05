"""Unit tests for domain models: pure logic, no files, no parsers."""

from __future__ import annotations

import dataclasses
import pickle
from datetime import timezone

import pytest

from sniffdash.domain.models import (
    Endpoint, Frame, FrozenMap, HttpRequest, HttpResponse, HttpTransaction, StatusClass, Transport,
)

CLIENT = Endpoint("10.0.0.2", 50000)
SERVER = Endpoint("93.184.216.34", 80)


def make_request(**overrides) -> HttpRequest:
    fields = dict(frame_number=4, timestamp=100.000, src=CLIENT, dst=SERVER,
                  method="GET", uri="/index.html", host="example.com",
                  headers=(("Host", "example.com"), ("User-Agent", "pytest")))
    return HttpRequest(**(fields | overrides))


def make_response(**overrides) -> HttpResponse:
    fields = dict(frame_number=5, timestamp=100.120, src=SERVER, dst=CLIENT,
                  status_code=200, reason="OK", headers=(("Content-Type", "text/html"),))
    return HttpResponse(**(fields | overrides))


# --- Endpoint ----------------------------------------------------------------------

class TestEndpoint:
    def test_str_ipv4_with_port(self):
        assert str(CLIENT) == "10.0.0.2:50000"

    def test_str_ipv6_uses_brackets(self):
        # Without brackets "::1:443" would be ambiguous (is 443 part of the address?).
        assert str(Endpoint("::1", 443)) == "[::1]:443"

    def test_str_without_port(self):
        assert str(Endpoint("10.0.0.1")) == "10.0.0.1"


# --- Frame -------------------------------------------------------------------------

class TestFrame:
    def test_normalizes_protocol_case(self):
        frame = Frame(number=1, timestamp=0.0, length=60, protocols=("ETH", "IP", "TCP"),
                      highest_protocol="TCP")
        assert frame.protocols == ("eth", "ip", "tcp")
        assert frame.highest_protocol == "tcp"
        assert frame.has_protocol("Tcp")

    @pytest.mark.parametrize("number", [0, -1])
    def test_rejects_non_positive_frame_number(self, number):
        # Wireshark numbering starts at 1. Frame 0 would break citations.
        with pytest.raises(ValueError):
            Frame(number=number, timestamp=0.0, length=10)

    def test_rejects_negative_length(self):
        with pytest.raises(ValueError):
            Frame(number=1, timestamp=0.0, length=-5)

    def test_is_immutable(self):
        frame = Frame(number=1, timestamp=0.0, length=10)
        with pytest.raises(dataclasses.FrozenInstanceError):
            frame.number = 2  # type: ignore[misc]

    def test_layers_are_deeply_immutable(self):
        frame = Frame(number=1, timestamp=0.0, length=10,
                      layers={"http": {"headers": [("Host", "x")]}})
        assert isinstance(frame.layers["http"], FrozenMap)
        assert frame.layers["http"]["headers"] == (("Host", "x"),)  # list → tuple
        with pytest.raises(TypeError):
            frame.layers["http"]["method"] = "POST"  # type: ignore[index]

    def test_datetime_is_utc(self):
        frame = Frame(number=1, timestamp=0.0, length=10)
        assert frame.datetime.tzinfo is timezone.utc
        assert frame.datetime.year == 1970

    def test_pickle_round_trip(self):
        # Streamlit's st.cache_data pickles cached values, so this MUST work.
        frame = Frame(number=7, timestamp=1.5, length=99, protocols=("ip", "udp"),
                      src=CLIENT, dst=SERVER, transport=Transport.UDP, stream_id=3,
                      layers={"udp": {"srcport": 1, "dstport": 2}})
        assert pickle.loads(pickle.dumps(frame)) == frame

    def test_layer_lookup_is_case_insensitive(self):
        frame = Frame(number=1, timestamp=0.0, length=1, layers={"dns": {"id": 1}})
        assert frame.layer("DNS") == {"id": 1}
        assert frame.layer("http") is None


# --- HTTP --------------------------------------------------------------------------

class TestStatusClass:
    @pytest.mark.parametrize("code, expected", [
        (100, StatusClass.INFORMATIONAL), (200, StatusClass.SUCCESS), (204, StatusClass.SUCCESS),
        (301, StatusClass.REDIRECTION), (404, StatusClass.CLIENT_ERROR), (503, StatusClass.SERVER_ERROR),
    ])
    def test_from_code(self, code, expected):
        assert StatusClass.from_code(code) is expected

    @pytest.mark.parametrize("code", [0, 99, 600, 999])
    def test_invalid_code(self, code):
        with pytest.raises(ValueError):
            StatusClass.from_code(code)


class TestHttpMessages:
    def test_header_lookup_is_case_insensitive(self):
        assert make_request().header("user-agent") == "pytest"
        assert make_request().header("X-Missing") is None

    def test_effective_host_prefers_host_field(self):
        assert make_request().effective_host == "example.com"

    def test_effective_host_falls_back_to_header(self):
        req = make_request(host=None, headers=(("host", "from-header.org"),))
        assert req.effective_host == "from-header.org"

    def test_effective_host_falls_back_to_destination_ip(self):
        # HTTP/1.0 requests may have no Host header at all.
        assert make_request(host=None, headers=()).effective_host == SERVER.ip

    def test_response_rejects_invalid_status(self):
        with pytest.raises(ValueError):
            make_response(status_code=42)

    def test_response_error_flag(self):
        assert make_response(status_code=404).is_error
        assert not make_response(status_code=301).is_error
        assert make_response(status_code=301).status_class is StatusClass.REDIRECTION


class TestHttpTransaction:
    def test_response_time_ms(self):
        # 100.120 - 100.000 = 0.120 s = 120 ms (float math → approx)
        tx = HttpTransaction("tx-1", make_request(), make_response())
        assert tx.response_time_ms == pytest.approx(120.0)
        assert tx.is_complete
        assert tx.status_code == 200

    def test_unanswered_transaction(self):
        tx = HttpTransaction("tx-2", make_request())
        assert tx.response_time_ms is None
        assert tx.status_code is None
        assert not tx.is_complete

    def test_response_before_request_is_rejected(self):
        # A pairing bug must fail loudly instead of producing negative latencies.
        with pytest.raises(ValueError, match="precedes"):
            HttpTransaction("tx-3", make_request(), make_response(timestamp=99.0))

    def test_pickle_round_trip(self):
        # AC7 names the HTTP models too, not only Frame (audit finding R4).
        tx = HttpTransaction("tx-5", make_request(), make_response())
        restored = pickle.loads(pickle.dumps(tx))
        assert restored == tx and restored.response_time_ms == pytest.approx(120.0)

    def test_zero_latency_is_allowed(self):
        tx = HttpTransaction("tx-4", make_request(), make_response(timestamp=100.0))
        assert tx.response_time_ms == 0.0

"""Shared pytest fixtures.

Test captures are GENERATED with Scapy at test time instead of being committed:
* the repo stays small and contains no real (possibly private) traffic;
* every expected value below is known exactly, because we wrote the packets.

The reference scenario ("http_scenario"), 13 frames:

  #   t (s)   what
  1   0.000   TCP SYN        10.0.0.2:50000 → 93.184.216.34:80   (TCP stream 0)
  2   0.010   TCP SYN-ACK
  3   0.020   TCP ACK
  4   0.030   GET /index.html   Host: example.com
  5   0.150   HTTP 200 OK  (body "<html>hello</html>")  → response time 120 ms
  6   0.200   GET /missing
  7   0.260   HTTP 404 Not Found                       → response time 60 ms
  8   0.300   DNS query  example.com  10.0.0.2:5353 → 8.8.8.8:53   (UDP stream 0)
  9   0.320   DNS answer 93.184.216.34
  10  0.400   TCP SYN        10.0.0.2:50001 → 93.184.216.34:80   (TCP stream 1)
  11  0.410   TCP SYN-ACK
  12  0.420   TCP ACK
  13  0.500   POST /api/login  (never answered → unanswered transaction)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import pytest

T0 = 1_700_000_000.0
CLIENT, SERVER, RESOLVER = "10.0.0.2", "93.184.216.34", "8.8.8.8"
CLIENT_MAC, GATEWAY_MAC = "02:00:00:00:00:02", "02:00:00:00:00:01"


@dataclass
class _TcpSession:
    """Tracks sequence numbers so generated TCP looks real to tshark's reassembly."""

    cport: int
    sport: int = 80
    c_seq: int = 1000
    s_seq: int = 5000
    packets: list = field(default_factory=list)

    def _pkt(self, from_client: bool, flags: str, payload: bytes, t: float):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether

        if from_client:
            eth = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
            ip = IP(src=CLIENT, dst=SERVER)
            tcp = TCP(sport=self.cport, dport=self.sport, flags=flags, seq=self.c_seq, ack=self.s_seq)
        else:
            eth = Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
            ip = IP(src=SERVER, dst=CLIENT)
            tcp = TCP(sport=self.sport, dport=self.cport, flags=flags, seq=self.s_seq, ack=self.c_seq)
        pkt = eth / ip / tcp / payload if payload else eth / ip / tcp
        pkt.time = T0 + t
        # Advance sequence numbers (SYN consumes 1, payload consumes len).
        advance = len(payload) + (1 if "S" in flags else 0)
        if from_client:
            self.c_seq += advance
        else:
            self.s_seq += advance
        return pkt

    def handshake(self, t: float) -> list:
        return [self._pkt(True, "S", b"", t), self._pkt(False, "SA", b"", t + 0.010),
                self._pkt(True, "A", b"", t + 0.020)]

    def client(self, payload: bytes, t: float):
        return self._pkt(True, "PA", payload, t)

    def server(self, payload: bytes, t: float):
        return self._pkt(False, "PA", payload, t)


def http_response(code: int, reason: str, body: bytes) -> bytes:
    head = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode()
    return head + body


def build_http_scenario() -> list:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    a = _TcpSession(cport=50000)
    pkts = a.handshake(0.000)
    pkts.append(a.client(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                         b"User-Agent: sniffdash-test\r\n\r\n", 0.030))
    pkts.append(a.server(http_response(200, "OK", b"<html>hello</html>"), 0.150))
    pkts.append(a.client(b"GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n", 0.200))
    pkts.append(a.server(http_response(404, "Not Found", b"nope"), 0.260))

    q = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=5353, dport=53) / \
        DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
    r = Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=RESOLVER, dst=CLIENT) / UDP(sport=53, dport=5353) / \
        DNS(id=0x1234, qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=SERVER))
    q.time, r.time = T0 + 0.300, T0 + 0.320
    pkts += [q, r]

    b = _TcpSession(cport=50001)
    pkts += b.handshake(0.400)
    body = b'{"user":"alice"}'
    pkts.append(b.client(b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\n"
                         b"Content-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body, 0.500))
    return pkts


# --- File fixtures (session-scoped: generated once per test run) ----------------------

@pytest.fixture(scope="session")
def capture_dir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("captures")


@pytest.fixture(scope="session")
def http_pcap(capture_dir) -> Path:
    from scapy.utils import wrpcap
    path = capture_dir / "http_scenario.pcap"
    wrpcap(str(path), build_http_scenario())
    return path


@pytest.fixture(scope="session")
def http_pcapng(capture_dir) -> Path:
    from scapy.utils import wrpcapng
    path = capture_dir / "http_scenario.pcapng"
    wrpcapng(str(path), build_http_scenario())
    return path


@pytest.fixture(scope="session")
def truncated_pcap(capture_dir, http_pcap) -> Path:
    """The reference capture with the last 10 bytes chopped off (packet 13 is cut short)."""
    path = capture_dir / "truncated.pcap"
    path.write_bytes(http_pcap.read_bytes()[:-10])
    return path


@pytest.fixture(scope="session")
def header_only_pcap(capture_dir) -> Path:
    """A valid pcap global header with zero packets."""
    path = capture_dir / "empty_capture.pcap"
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return path


@pytest.fixture(scope="session")
def garbage_file(capture_dir) -> Path:
    path = capture_dir / "not_a_capture.pcap"
    path.write_bytes(b"This is a text file pretending to be a pcap.\n" * 10)
    return path


@pytest.fixture(scope="session")
def empty_file(capture_dir) -> Path:
    path = capture_dir / "zero_bytes.pcap"
    path.write_bytes(b"")
    return path


# --- Backend availability -------------------------------------------------------------

def tshark_available() -> bool:
    from sniffdash.parsing.pyshark_parser import PySharkParser
    return PySharkParser.is_available()


requires_tshark = pytest.mark.skipif(not tshark_available(), reason="tshark (Wireshark) not installed")

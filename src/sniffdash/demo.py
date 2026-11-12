"""Synthetic demo captures: known traffic with exactly known answers.

Used in two places: by the test suite (ground truth for every expected value) and
by new users who want something to open in the dashboard right away:

    python -m sniffdash.demo captures

writes ``demo_http.pcap`` (the 13-frame reference scenario below) and
``demo_https.pcap`` (three encrypted flows: video-like, download, API polling).

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
import sys
from dataclasses import dataclass, field
from pathlib import Path

T0 = 1_700_000_000.0
CLIENT, SERVER, RESOLVER = "10.0.0.2", "93.184.216.34", "8.8.8.8"
CLIENT_MAC, GATEWAY_MAC = "02:00:00:00:00:02", "02:00:00:00:00:01"


@dataclass
class TcpSession:
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

    a = TcpSession(cport=50000)
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

    b = TcpSession(cport=50001)
    pkts += b.handshake(0.400)
    body = b'{"user":"alice"}'
    pkts.append(b.client(b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\n"
                         b"Content-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body, 0.500))
    return pkts


def tls_client_hello(sni: bytes) -> bytes:
    """A minimal but valid TLS 1.2-style ClientHello record carrying an SNI extension.

    Built by hand (struct) so nothing depends on Scapy's optional TLS layer.
    Layout: record header → handshake header → ClientHello body → SNI extension.
    """
    name = b"\x00" + struct.pack("!H", len(sni)) + sni                       # host_name entry
    sni_ext = struct.pack("!HH", 0, len(name) + 2) + struct.pack("!H", len(name)) + name
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00"                            # version, random, no session
            + struct.pack("!H", 4) + b"\x13\x01\x13\x02"                     # 2 cipher suites
            + b"\x01\x00"                                                    # 1 compression method: null
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body           # type 1 = ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake  # type 22 = handshake


def build_edge_cases() -> list:
    """Two frames that exercise rarely-hit paths:

      1  TLS ClientHello to 1.2.3.4:443 with SNI "secure.example.com"
      2  DNS query whose question section is cut off (malformed)
    """
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    eth = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
    tls = eth / IP(src=CLIENT, dst="1.2.3.4") / TCP(sport=50010, dport=443, flags="PA", seq=1, ack=1) / \
        tls_client_hello(b"secure.example.com")
    bad_dns = eth / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=5000, dport=53) / \
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07exa"  # label says 7 bytes, only 3 follow
    tls.time, bad_dns.time = T0 + 1.0, T0 + 2.0
    return [tls, bad_dns]


def build_pipelined() -> list:
    """Frames 4-5: GET /a, GET /b sent back-to-back; frames 6-7: 200 (for /a), 404 (for /b).

    tshark's own request/response links get this WRONG (they pair 6 with /b).
    """
    s = TcpSession(cport=50100)
    return s.handshake(0.0) + [
        s.client(b"GET /a HTTP/1.1\r\nHost: x.com\r\n\r\n", 0.10),
        s.client(b"GET /b HTTP/1.1\r\nHost: x.com\r\n\r\n", 0.11),
        s.server(http_response(200, "OK", b"AAA"), 0.30),
        s.server(http_response(404, "Not Found", b"B"), 0.35),
    ]


def build_port_reuse() -> list:
    """Two connections on the SAME 4-tuple. The first leaves GET /lost unanswered
    and closes; the second (new SYN, new sequence numbers) gets 200 for GET /second.
    Frames: 1-3 handshake, 4 GET /lost, 5-6 FIN, 7-9 handshake, 10 GET /second, 11 200.
    """
    first = TcpSession(cport=50200)
    pkts = first.handshake(0.0) + [
        first.client(b"GET /lost HTTP/1.1\r\nHost: x\r\n\r\n", 0.1),
        first._pkt(True, "FA", b"", 0.3),
        first._pkt(False, "FA", b"", 0.31),
    ]
    second = TcpSession(cport=50200, c_seq=90000, s_seq=70000)
    return pkts + second.handshake(1.0) + [
        second.client(b"GET /second HTTP/1.1\r\nHost: x\r\n\r\n", 1.1),
        second.server(http_response(200, "OK", b"2"), 1.2),
    ]


def build_retransmission() -> list:
    """Frame 4 GET /retx; frame 5 = the identical segment retransmitted; frame 6 200 OK."""
    s = TcpSession(cport=50300)
    pkts = s.handshake(0.0)
    request = s.client(b"GET /retx HTTP/1.1\r\nHost: x\r\n\r\n", 0.1)
    duplicate = request.copy()
    duplicate.time = request.time + 0.2
    return pkts + [request, duplicate, s.server(http_response(200, "OK", b"r"), 0.4)]


def build_two_in_one_segment() -> list:
    """Frames 4-5: GET /a, GET /b; frame 6: ONE segment carrying both responses (200 then 404)."""
    s = TcpSession(cport=50400)
    return s.handshake(0.0) + [
        s.client(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n", 0.1),
        s.client(b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n", 0.11),
        s.server(http_response(200, "OK", b"A") + http_response(404, "Not Found", b"B"), 0.3),
    ]


def tls_app_data(body_size: int) -> bytes:
    """One TLS application-data record (type 23, TLS 1.2 framing) with an opaque body.

    Real HTTPS payloads look exactly like this from the outside: a 5-byte record
    header followed by ciphertext the observer cannot read.
    """
    return b"\x17\x03\x03" + struct.pack("!H", body_size) + bytes([0xA5]) * body_size


def _https_session(cport: int, sni: bytes, t0: float) -> tuple[TcpSession, list]:
    s = TcpSession(cport=cport, sport=443)
    return s, s.handshake(t0) + [s.client(tls_client_hello(sni), t0 + 0.03)]


def _download_burst(s: TcpSession, total: int, t: float, segment: int = 1400) -> list:
    """Server sends `total` bytes as back-to-back 1400-byte TLS records, 1 ms apart."""
    packets, sent = [], 0
    while sent < total:
        body = min(segment - 5, total - sent)
        packets.append(s.server(tls_app_data(body), t))
        sent, t = sent + body, t + 0.001
    return packets


def build_https_flows() -> list:
    """Three encrypted connections to port 443 (TCP streams 0, 1, 2):

      stream 0  video.example.com    5 bursts of 250 KB every 3 s over 12 s  → video_streaming
      stream 1  images.example.com   one 300 KB burst                        → file_or_image_download
      stream 2  api.example.com      6 small request/response pairs, 2 s apart → api_polling
    """
    video, packets = _https_session(51000, b"video.example.com", 0.0)
    for i in range(5):
        t = 1.0 + 3.0 * i
        packets += [video.client(tls_app_data(120), t)] + _download_burst(video, 250_000, t + 0.02)

    image, p = _https_session(51001, b"images.example.com", 0.2)
    packets += p + [image.client(tls_app_data(150), 1.2)] + _download_burst(image, 300_000, 1.25)

    api, p = _https_session(51002, b"api.example.com", 0.4)
    packets += p
    for i in range(6):
        t = 1.5 + 2.0 * i
        packets += [api.client(tls_app_data(200), t), api.server(tls_app_data(800), t + 0.04)]

    return sorted(packets, key=lambda pkt: float(pkt.time))  # interleave like a real capture


def write_pcap(path: Path, packets: list) -> Path:
    from scapy.utils import wrpcap
    path = Path(path)
    wrpcap(str(path), packets)
    return path


DEMO_CAPTURES = {
    "demo_http.pcap": build_http_scenario,
    "demo_https.pcap": build_https_flows,
}


def write_demo_captures(directory: Path) -> list[Path]:
    """Write every demo capture into ``directory`` (created if needed)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return [write_pcap(directory / name, build()) for name, build in DEMO_CAPTURES.items()]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    target = Path(args[0]) if args else Path("captures")
    for path in write_demo_captures(target):
        print(f"wrote {path}")
    print("Open the dashboard with:  streamlit run app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

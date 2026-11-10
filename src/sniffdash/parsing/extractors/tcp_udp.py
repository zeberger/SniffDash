"""Transport layer extractors → layer keys ``tcp`` and ``udp``.

``stream`` is a conversation index: every packet of one TCP connection (or one
UDP 5-tuple) shares the same number. tshark computes it (``tcp.stream``);
Scapy has no such concept, so ``ScapyParser`` fills it in with a StreamIndexer.
"""

from __future__ import annotations

from typing import Any

from sniffdash.parsing.extractors.base import (
    Backend, LayerExtractor, extractor_registry, pyshark_field, pyshark_has_layer, to_int,
)

# TCP flag bits → letters, in the order Wireshark shows them.
_TCP_FLAG_BITS = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"),
                  (0x20, "U"), (0x40, "E"), (0x80, "C"))


def flags_to_str(bits: int | None) -> str:
    if bits is None:
        return ""
    return "".join(letter for bit, letter in _TCP_FLAG_BITS if bits & bit)


@extractor_registry.register(Backend.PYSHARK)
class PySharkTcpExtractor(LayerExtractor[Any]):
    layer = "tcp"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "tcp")

    def extract(self, packet: Any) -> dict[str, Any]:
        tcp = packet["tcp"]
        return {
            "srcport": to_int(pyshark_field(tcp, "srcport")),
            "dstport": to_int(pyshark_field(tcp, "dstport")),
            "stream": to_int(pyshark_field(tcp, "stream")),
            "seq": to_int(pyshark_field(tcp, "seq")),        # relative seq (Wireshark default)
            "ack": to_int(pyshark_field(tcp, "ack")),
            "flags": flags_to_str(to_int(pyshark_field(tcp, "flags"))),
            "payload_len": to_int(pyshark_field(tcp, "len")) or 0,
        }


@extractor_registry.register(Backend.PYSHARK)
class PySharkUdpExtractor(LayerExtractor[Any]):
    layer = "udp"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "udp")

    def extract(self, packet: Any) -> dict[str, Any]:
        udp = packet["udp"]
        return {
            "srcport": to_int(pyshark_field(udp, "srcport")),
            "dstport": to_int(pyshark_field(udp, "dstport")),
            "stream": to_int(pyshark_field(udp, "stream")),
        }


@extractor_registry.register(Backend.SCAPY)
class ScapyTcpExtractor(LayerExtractor[Any]):
    layer = "tcp"

    def applies_to(self, packet: Any) -> bool:
        from scapy.layers.inet import TCP
        return packet.haslayer(TCP)

    def extract(self, packet: Any) -> dict[str, Any]:
        from scapy.layers.inet import TCP
        tcp = packet[TCP]
        return {
            "srcport": int(tcp.sport),
            "dstport": int(tcp.dport),
            "stream": None,                 # assigned by ScapyParser's StreamIndexer
            "seq": int(tcp.seq),            # absolute seq (Scapy has no relative numbering)
            "ack": int(tcp.ack),
            "flags": flags_to_str(int(tcp.flags)),
            "payload_len": self._payload_len(packet, tcp),
        }

    @staticmethod
    def _payload_len(packet: Any, tcp: Any) -> int:
        """TCP data length from the IP header, as Wireshark computes ``tcp.len``.

        ``len(tcp.payload)`` would also count Ethernet padding (the zero bytes that
        pad short frames to 60 bytes), making a bare ACK look like it carries data.
        """
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        header = (tcp.dataofs or 5) * 4
        if packet.haslayer(IP) and packet[IP].len is not None:
            ip = packet[IP]
            return max(0, ip.len - ip.ihl * 4 - header)
        if packet.haslayer(IPv6) and packet[IPv6].plen is not None:
            return max(0, packet[IPv6].plen - header)  # assumes no extension headers
        return len(bytes(tcp.payload))


@extractor_registry.register(Backend.SCAPY)
class ScapyUdpExtractor(LayerExtractor[Any]):
    layer = "udp"

    def applies_to(self, packet: Any) -> bool:
        from scapy.layers.inet import UDP
        return packet.haslayer(UDP)

    def extract(self, packet: Any) -> dict[str, Any]:
        from scapy.layers.inet import UDP
        udp = packet[UDP]
        return {"srcport": int(udp.sport), "dstport": int(udp.dport), "stream": None}

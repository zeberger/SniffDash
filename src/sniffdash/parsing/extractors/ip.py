"""Network layer (IPv4 / IPv6) extractors → layer key ``ip``.

IPv4 and IPv6 are normalized into ONE ``ip`` layer (with a ``version`` field) so
that analyzers and the frame assembler never need to care which one was used.
"""

from __future__ import annotations

from typing import Any

from sniffdash.parsing.extractors.base import (
    Backend, LayerExtractor, extractor_registry, pyshark_field, pyshark_has_layer, to_int,
)


@extractor_registry.register(Backend.PYSHARK)
class PySharkIpExtractor(LayerExtractor[Any]):
    layer = "ip"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "ip") or pyshark_has_layer(packet, "ipv6")

    def extract(self, packet: Any) -> dict[str, Any]:
        if pyshark_has_layer(packet, "ip"):
            layer = packet["ip"]
            return {"src": pyshark_field(layer, "src"), "dst": pyshark_field(layer, "dst"),
                    "version": 4, "ttl": to_int(pyshark_field(layer, "ttl"))}
        layer = packet["ipv6"]
        return {"src": pyshark_field(layer, "src"), "dst": pyshark_field(layer, "dst"),
                "version": 6, "ttl": to_int(pyshark_field(layer, "hlim"))}


@extractor_registry.register(Backend.SCAPY)
class ScapyIpExtractor(LayerExtractor[Any]):
    layer = "ip"

    def applies_to(self, packet: Any) -> bool:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        return packet.haslayer(IP) or packet.haslayer(IPv6)

    def extract(self, packet: Any) -> dict[str, Any]:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if packet.haslayer(IP):
            ip = packet[IP]
            return {"src": ip.src, "dst": ip.dst, "version": 4, "ttl": ip.ttl}
        ip6 = packet[IPv6]
        return {"src": ip6.src, "dst": ip6.dst, "version": 6, "ttl": ip6.hlim}

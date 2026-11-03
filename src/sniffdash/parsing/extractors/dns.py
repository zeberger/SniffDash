"""DNS extractors → layer key ``dns``.

Step 1 only extracts the fields. A full DNS analyzer is a future-assignment
extension point, and it will read exactly this schema.
"""

from __future__ import annotations

from typing import Any

from sniffdash.parsing.extractors.base import (
    Backend, LayerExtractor, extractor_registry, pyshark_all_values, pyshark_field,
    pyshark_has_layer, to_bool, to_int,
)


@extractor_registry.register(Backend.PYSHARK)
class PySharkDnsExtractor(LayerExtractor[Any]):
    layer = "dns"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "dns")

    def extract(self, packet: Any) -> dict[str, Any]:
        dns = packet["dns"]
        return {
            "id": to_int(pyshark_field(dns, "id")),
            "is_response": bool(to_bool(pyshark_field(dns, "flags_response"))),
            "qname": pyshark_field(dns, "qry_name"),
            "qtype": to_int(pyshark_field(dns, "qry_type")),
            "rcode": to_int(pyshark_field(dns, "flags_rcode")),
            "answers": pyshark_all_values(dns, "a") + pyshark_all_values(dns, "aaaa"),
        }


@extractor_registry.register(Backend.SCAPY)
class ScapyDnsExtractor(LayerExtractor[Any]):
    layer = "dns"

    def applies_to(self, packet: Any) -> bool:
        from scapy.layers.dns import DNS
        return packet.haslayer(DNS)

    def extract(self, packet: Any) -> dict[str, Any]:
        from scapy.layers.dns import DNS
        dns = packet[DNS]
        question = dns.qd[0] if dns.qd else None
        qname = question.qname.decode(errors="replace").rstrip(".") if question else None
        answers = [str(rr.rdata) for rr in (dns.an or []) if getattr(rr, "type", None) in (1, 28)]
        return {
            "id": int(dns.id),
            "is_response": bool(dns.qr),
            "qname": qname,
            "qtype": int(question.qtype) if question else None,
            "rcode": int(dns.rcode) if dns.qr else None,
            "answers": answers,
        }

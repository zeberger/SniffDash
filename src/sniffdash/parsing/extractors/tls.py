"""TLS extractor → layer key ``tls`` (PyShark only).

Scapy's TLS dissector needs the optional ``cryptography`` package and a manual
``load_layer("tls")``, so in the Scapy fallback TLS traffic shows up as plain
TCP. This is a documented limitation of the fallback backend. Note that adding
a Scapy TLS extractor later would only mean adding a class to this file.
"""

from __future__ import annotations

from typing import Any

from sniffdash.parsing.extractors.base import (
    Backend, LayerExtractor, extractor_registry, pyshark_field, pyshark_has_layer, to_int,
)


@extractor_registry.register(Backend.PYSHARK)
class PySharkTlsExtractor(LayerExtractor[Any]):
    layer = "tls"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "tls")

    def extract(self, packet: Any) -> dict[str, Any]:
        tls = packet["tls"]
        return {
            "content_type": to_int(pyshark_field(tls, "record_content_type")),
            "handshake_type": to_int(pyshark_field(tls, "handshake_type")),
            "version": pyshark_field(tls, "record_version"),
            "sni": pyshark_field(tls, "handshake_extensions_server_name"),
        }

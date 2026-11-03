"""HTTP/1.x extractors → layer key ``http``.

These extract *messages*; pairing requests with responses is an analysis
concern (Step 2, ``analysis/protocols/http/pairing.py``). With tshark, though,
we also keep Wireshark's own hints (``request_in`` / ``response_in`` / ``time``),
which give the pairing strategy a high-confidence first choice.

Known limitation: if several pipelined HTTP messages share one TCP segment,
only the first is extracted. This is rare in practice.
"""

from __future__ import annotations

from typing import Any

from sniffdash.parsing.extractors.base import (
    Backend, LayerExtractor, decode_body, extractor_registry, parse_header_lines,
    pyshark_all_values, pyshark_field, pyshark_has_layer, to_int, tshark_bytes,
)


def _empty_message() -> dict[str, Any]:
    return {
        "kind": None, "method": None, "uri": None, "host": None, "version": None,
        "status_code": None, "reason": None, "headers": [], "body": "",
        "request_in": None, "response_in": None, "time": None,
    }


@extractor_registry.register(Backend.PYSHARK)
class PySharkHttpExtractor(LayerExtractor[Any]):
    layer = "http"

    def applies_to(self, packet: Any) -> bool:
        return pyshark_has_layer(packet, "http")

    def extract(self, packet: Any) -> dict[str, Any]:
        http = packet["http"]
        msg = _empty_message()
        method = pyshark_field(http, "request_method")
        code = to_int(pyshark_field(http, "response_code"))
        if method:
            msg |= {
                "kind": "request",
                "method": method,
                "uri": pyshark_field(http, "request_uri"),
                "host": pyshark_field(http, "host"),
                "version": pyshark_field(http, "request_version"),
                "headers": parse_header_lines(pyshark_all_values(http, "request_line")),
                "response_in": to_int(pyshark_field(http, "response_in")),
            }
        elif code is not None:
            time = pyshark_field(http, "time")
            msg |= {
                "kind": "response",
                "status_code": code,
                "reason": pyshark_field(http, "response_phrase") or "",
                "version": pyshark_field(http, "response_version"),
                "headers": parse_header_lines(pyshark_all_values(http, "response_line")),
                "request_in": to_int(pyshark_field(http, "request_in")),
                "time": float(time) if time else None,
                "uri": pyshark_field(http, "response_for_uri") or pyshark_field(http, "request_uri"),
            }
        # else: continuation segment of a body (kind stays None)
        msg["body"] = decode_body(tshark_bytes(pyshark_field(http, "file_data")),
                                  self._options.body_char_limit)
        return msg


# Scapy's HTTP layer exposes each known header as a field ("User_Agent").
_SCAPY_NON_HEADER_FIELDS = {"Method", "Path", "Http_Version", "Status_Code",
                            "Reason_Phrase", "Unknown_Headers"}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    return value.decode("latin-1") if isinstance(value, bytes) else str(value)


@extractor_registry.register(Backend.SCAPY)
class ScapyHttpExtractor(LayerExtractor[Any]):
    """Requires ``scapy.layers.http`` to be imported BEFORE reading the file
    (ScapyParser does this); Scapy then dissects TCP port 80/8080 as HTTP."""

    layer = "http"

    def applies_to(self, packet: Any) -> bool:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        return packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)

    def extract(self, packet: Any) -> dict[str, Any]:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        msg = _empty_message()
        if packet.haslayer(HTTPRequest):
            layer = packet[HTTPRequest]
            msg |= {
                "kind": "request",
                "method": _text(layer.Method),
                "uri": _text(layer.Path),
                "host": _text(layer.Host),
                "version": _text(layer.Http_Version),
            }
        else:
            layer = packet[HTTPResponse]
            msg |= {
                "kind": "response",
                "status_code": to_int(_text(layer.Status_Code)),
                "reason": _text(layer.Reason_Phrase) or "",
                "version": _text(layer.Http_Version),
            }
        msg["headers"] = self._headers(layer)
        msg["body"] = decode_body(bytes(layer.payload) or None, self._options.body_char_limit)
        return msg

    @staticmethod
    def _headers(layer: Any) -> list[tuple[str, str]]:
        headers = [
            (name.replace("_", "-"), _text(value) or "")
            for name, value in layer.fields.items()
            if name not in _SCAPY_NON_HEADER_FIELDS and value is not None
        ]
        for name, value in (layer.fields.get("Unknown_Headers") or {}).items():
            headers.append((_text(name) or "", _text(value) or ""))
        return headers

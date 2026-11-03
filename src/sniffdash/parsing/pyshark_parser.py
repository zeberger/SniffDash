"""PySharkParser: primary backend, driven by Wireshark's tshark.

Why it is the primary backend: tshark runs Wireshark's own dissectors, including
TCP reassembly, HTTP/TLS/DNS decoding, Wireshark-identical frame numbers and
``tcp.stream`` indexes, and request↔response links. The trade-off is speed:
roughly 1-3k packets/s, because every packet crosses a process boundary as XML.

Threading note: Streamlit runs scripts in worker threads that have no asyncio
event loop. PyShark needs one, so we create a private loop per parse and always
close it, which avoids leaking tshark processes.
"""

from __future__ import annotations

import asyncio
import functools
import importlib.util
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from sniffdash.domain.errors import IssueSeverity, ParseIssue, ParserUnavailableError
from sniffdash.parsing.base import PacketParser, RawFrameMeta
from sniffdash.parsing.extractors.base import Backend, LayerExtractor
from sniffdash.parsing.options import ParserOptions
from sniffdash.parsing.tshark_locator import find_tshark


@functools.cache
def _idempotent_capture_class() -> type:
    """pyshark.FileCapture whose close() runs only once.

    pyshark's ``__del__`` calls ``close()`` a second time, after we have already
    closed our private event loop, which raises "Event loop is closed". Built
    lazily so that importing this module never requires pyshark.
    """
    import pyshark

    class _IdempotentFileCapture(pyshark.FileCapture):
        _sniffdash_closed = False

        def close(self) -> None:
            if not self._sniffdash_closed:
                self._sniffdash_closed = True
                super().close()

    return _IdempotentFileCapture


class PySharkParser(PacketParser[Any]):
    name = "pyshark"
    backend = Backend.PYSHARK

    def __init__(self, options: ParserOptions | None = None,
                 extractors: Sequence[LayerExtractor] | None = None,
                 tshark_path: str | None = None) -> None:
        super().__init__(options, extractors)
        self._tshark_path = tshark_path or find_tshark()

    @classmethod
    def is_available(cls) -> bool:
        return importlib.util.find_spec("pyshark") is not None and find_tshark() is not None

    def _iter_raw_packets(self, path: Path) -> Iterator[Any]:
        if self._tshark_path is None or importlib.util.find_spec("pyshark") is None:
            raise ParserUnavailableError("PyShark backend needs both the 'pyshark' package and tshark (Wireshark).")
        loop = asyncio.new_event_loop()
        capture = _idempotent_capture_class()(
            str(path), keep_packets=False, tshark_path=self._tshark_path, eventloop=loop,
            # "-2" = two-pass analysis. Without it tshark cannot fill FORWARD
            # references such as a request's http.response_in (the response comes later).
            custom_parameters=["-2"],
        )
        try:
            yield from capture
        finally:
            try:
                capture.close()
            finally:
                loop.close()

    def _read_meta(self, packet: Any, index: int) -> RawFrameMeta:
        return RawFrameMeta(
            number=int(packet.number) if getattr(packet, "number", None) else index,
            timestamp=float(packet.sniff_timestamp),
            length=int(packet.length),
            protocols=tuple(packet.frame_info.protocols.split(":")),
        )

    def _packet_issues(self, packet: Any, meta: RawFrameMeta) -> list[ParseIssue]:
        # tshark marks undecodable packets with a pseudo-layer "_ws.malformed".
        names = {layer.layer_name for layer in packet.layers}
        if "_ws.malformed" in names or "_ws.malformed" in meta.protocols:
            return [ParseIssue("Wireshark flagged this packet as malformed.",
                               IssueSeverity.WARNING, meta.number)]
        return []

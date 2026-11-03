"""ParserFactory: decides WHICH parser to build (Factory pattern).

Callers (the application layer) ask for "a parser for this file" and never name
a concrete class. That lets us switch the default backend, add new ones (e.g. a
fast ``tshark -T ek`` streaming parser), or fall back automatically, without
changing any caller.

Selection rules:
* explicit backend requested → that backend, or ``ParserUnavailableError``
* AUTO → the first *available* backend by priority (PyShark, then Scapy)
"""

from __future__ import annotations

from pathlib import Path

from sniffdash.domain.errors import ParserUnavailableError
from sniffdash.parsing.base import PacketParser
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.formats import detect_capture_format
from sniffdash.parsing.options import ParserOptions


class ParserFactory:
    def __init__(self, options: ParserOptions | None = None) -> None:
        self._options = options or ParserOptions()
        # backend → (priority, parser class); lower priority number = preferred
        self._registry: dict[Backend, tuple[int, type[PacketParser]]] = {}

    def register(self, parser_cls: type[PacketParser], *, priority: int) -> None:
        self._registry[parser_cls.backend] = (priority, parser_cls)

    def available_backends(self) -> list[Backend]:
        ordered = sorted(self._registry.items(), key=lambda item: item[1][0])
        return [backend for backend, (_, cls) in ordered if cls.is_available()]

    def create(self, path: Path, backend: Backend | None = None) -> PacketParser:
        detect_capture_format(Path(path))  # fail fast on non-captures, before choosing
        if backend is not None:
            if backend not in self._registry:
                raise ParserUnavailableError(f"No parser registered for backend '{backend}'.")
            cls = self._registry[backend][1]
            if not cls.is_available():
                raise ParserUnavailableError(f"Parser backend '{backend}' is not installed.")
            return cls(self._options)

        available = self.available_backends()
        if not available:
            raise ParserUnavailableError(
                "No parser backend is available. Install Wireshark (tshark) or `pip install scapy`.")
        return self._registry[available[0]][1](self._options)

    @classmethod
    def default(cls, options: ParserOptions | None = None) -> ParserFactory:
        """Factory pre-loaded with the built-in backends."""
        from sniffdash.parsing.pyshark_parser import PySharkParser
        from sniffdash.parsing.scapy_parser import ScapyParser

        factory = cls(options)
        factory.register(PySharkParser, priority=10)
        factory.register(ScapyParser, priority=20)
        return factory

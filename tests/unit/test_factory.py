"""Unit tests for ParserFactory selection logic, using stub parser classes."""

from __future__ import annotations

import pytest

from sniffdash.domain.errors import ParserUnavailableError, UnsupportedFormatError
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.factory import ParserFactory
from sniffdash.parsing.pyshark_parser import PySharkParser
from sniffdash.parsing.scapy_parser import ScapyParser


def stub(backend: Backend, available: bool):
    """A parser subclass whose availability we control."""
    base = PySharkParser if backend is Backend.PYSHARK else ScapyParser
    return type(f"Stub{backend.value}", (base,), {"is_available": classmethod(lambda cls: available)})


def factory_with(pyshark_ok: bool, scapy_ok: bool) -> ParserFactory:
    factory = ParserFactory()
    factory.register(stub(Backend.PYSHARK, pyshark_ok), priority=10)
    factory.register(stub(Backend.SCAPY, scapy_ok), priority=20)
    return factory


def test_auto_prefers_highest_priority(header_only_pcap):
    assert factory_with(True, True).create(header_only_pcap).backend is Backend.PYSHARK


def test_auto_falls_back_when_tshark_missing(header_only_pcap):
    assert factory_with(False, True).create(header_only_pcap).backend is Backend.SCAPY


def test_explicit_backend_is_respected(header_only_pcap):
    assert factory_with(True, True).create(header_only_pcap, Backend.SCAPY).backend is Backend.SCAPY


def test_explicit_unavailable_backend_raises(header_only_pcap):
    # Explicit requests do NOT silently fall back: the caller asked for something specific.
    with pytest.raises(ParserUnavailableError):
        factory_with(False, True).create(header_only_pcap, Backend.PYSHARK)


def test_no_backend_available(header_only_pcap):
    with pytest.raises(ParserUnavailableError, match="Install"):
        factory_with(False, False).create(header_only_pcap)


def test_rejects_non_capture_before_selecting(garbage_file):
    with pytest.raises(UnsupportedFormatError):
        factory_with(True, True).create(garbage_file)


def test_default_factory_registers_builtins():
    assert set(ParserFactory.default().available_backends()) <= {Backend.PYSHARK, Backend.SCAPY}
    assert Backend.SCAPY in ParserFactory.default().available_backends()

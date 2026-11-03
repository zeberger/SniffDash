"""ScapyParser: pure-Python fallback backend (no Wireshark needed).

Differences from tshark that we compensate for:
* Scapy has no ``tcp.stream`` index, so ``StreamIndexer`` assigns one with the
  same numbering rule: streams are numbered 0, 1, 2… in order of first appearance.
* Scapy names layers by class (``IP``, ``HTTPRequest``), so ``_LAYER_NAMES`` maps
  them to Wireshark-style protocol names, which keeps statistics identical.
* Scapy does no TCP reassembly, so HTTP messages split across segments are
  only partially decoded. This is documented as a limitation of the fallback.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sniffdash.parsing.base import PacketParser, RawFrameMeta
from sniffdash.parsing.extractors.base import Backend

# Scapy layer class name → Wireshark protocol name (None = not a protocol, skip).
_LAYER_NAMES: dict[str, str | None] = {
    "Ether": "eth", "CookedLinux": "sll", "CookedLinuxV2": "sll", "Dot1Q": "vlan",
    "IP": "ip", "IPv6": "ipv6", "ARP": "arp", "ICMP": "icmp",
    "TCP": "tcp", "UDP": "udp", "DNS": "dns", "DNSQR": None, "DNSRR": None,
    "HTTP": None, "HTTPRequest": "http", "HTTPResponse": "http",
    "Raw": "data", "Padding": None,
}


class StreamIndexer:
    """Assigns Wireshark-style conversation indexes (separately per transport)."""

    def __init__(self) -> None:
        self._ids: dict[tuple[str, tuple, tuple], int] = {}
        self._next: dict[str, int] = {}

    def index(self, transport: str, a: tuple[str, int], b: tuple[str, int]) -> int:
        lo, hi = sorted((a, b))  # direction-independent key: A→B and B→A are one stream
        key = (transport, lo, hi)
        if key not in self._ids:
            self._ids[key] = self._next.get(transport, 0)
            self._next[transport] = self._ids[key] + 1
        return self._ids[key]


class ScapyParser(PacketParser[Any]):
    name = "scapy"
    backend = Backend.SCAPY

    @classmethod
    def is_available(cls) -> bool:
        return importlib.util.find_spec("scapy") is not None

    def _iter_raw_packets(self, path: Path) -> Iterator[Any]:
        import scapy.layers.http  # noqa: F401 (import binds HTTP to TCP/80 before reading)
        from scapy.utils import PcapReader

        self._streams = StreamIndexer()  # fresh numbering for every file
        with PcapReader(str(path)) as reader:
            yield from reader

    def _read_meta(self, packet: Any, index: int) -> RawFrameMeta:
        protocols: list[str] = []
        for layer_cls in packet.layers():
            name = _LAYER_NAMES.get(layer_cls.__name__, layer_cls.__name__.lower())
            if name and name not in protocols:
                protocols.append(name)
        return RawFrameMeta(
            number=index,  # pcap order == Wireshark's frame numbering
            timestamp=float(packet.time),
            length=int(getattr(packet, "wirelen", None) or len(packet)),
            protocols=tuple(protocols),
        )

    def _post_process(self, packet: Any, layers: dict[str, dict[str, Any]]) -> None:
        ip = layers.get("ip")
        if not ip:
            return
        for transport in ("tcp", "udp"):
            t = layers.get(transport)
            if t is not None:
                t["stream"] = self._streams.index(
                    transport, (ip["src"], t["srcport"]), (ip["dst"], t["dstport"]))

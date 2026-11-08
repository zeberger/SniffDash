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
    """Assigns Wireshark-style conversation indexes (separately per transport).

    Port reuse: when a client opens a NEW TCP connection on a 4-tuple seen before,
    tshark gives it a new stream index. A pure SYN (``syn_seq`` given) with a
    different initial sequence number than the one that opened the current stream
    does the same here. A retransmitted SYN (same sequence number) stays in its stream.
    """

    def __init__(self) -> None:
        self._ids: dict[tuple[str, tuple, tuple], int] = {}
        self._syn_seq: dict[tuple[str, tuple, tuple], int] = {}
        self._next: dict[str, int] = {}

    def index(self, transport: str, a: tuple[str, int], b: tuple[str, int],
              syn_seq: int | None = None) -> int:
        lo, hi = sorted((a, b))  # direction-independent key: A→B and B→A are one stream
        key = (transport, lo, hi)
        new_connection = (key in self._ids and syn_seq is not None
                          and self._syn_seq.get(key) != syn_seq)
        if key not in self._ids or new_connection:
            self._ids[key] = self._next.get(transport, 0)
            self._next[transport] = self._ids[key] + 1
        if syn_seq is not None:
            self._syn_seq[key] = syn_seq
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
                flags = t.get("flags", "")
                pure_syn = transport == "tcp" and "S" in flags and "A" not in flags
                t["stream"] = self._streams.index(
                    transport, (ip["src"], t["srcport"]), (ip["dst"], t["dstport"]),
                    syn_seq=t["seq"] if pure_syn else None)

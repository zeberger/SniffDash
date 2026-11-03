"""Capture-format detection and structural integrity scanning.

Both functions read only file *headers* and record lengths, never payloads, so
they are fast even for large files. They run before any parser backend:

* ``detect_capture_format`` rejects non-captures early, by **magic bytes**. File
  extensions are unreliable: users rename files, and browsers drop extensions on
  upload.
* ``scan_integrity`` walks the record structure to find out whether the file was
  cut short (common when a capture is stopped abruptly or a download fails).
  Doing this here, instead of in each backend, gives identical behavior for
  PyShark and Scapy.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sniffdash.domain.errors import CaptureError, CorruptCaptureError, UnsupportedFormatError


class CaptureFormat(StrEnum):
    PCAP = "pcap"            # classic libpcap, microsecond timestamps
    PCAP_NS = "pcap-ns"      # classic libpcap, nanosecond timestamps
    PCAPNG = "pcapng"        # next-generation block format (Wireshark default)


# Magic number → (format, struct byte-order prefix). Both byte orders exist in the wild.
_PCAP_MAGIC: dict[bytes, tuple[CaptureFormat, str]] = {
    bytes.fromhex("d4c3b2a1"): (CaptureFormat.PCAP, "<"),
    bytes.fromhex("a1b2c3d4"): (CaptureFormat.PCAP, ">"),
    bytes.fromhex("4d3cb2a1"): (CaptureFormat.PCAP_NS, "<"),
    bytes.fromhex("a1b23c4d"): (CaptureFormat.PCAP_NS, ">"),
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_PCAPNG_BOM = 0x1A2B3C4D

_PCAP_GLOBAL_HEADER = 24
_PCAP_RECORD_HEADER = 16
_PCAPNG_PACKET_BLOCKS = {0x00000002, 0x00000003, 0x00000006}  # obsolete PB, SPB, EPB
_MAX_RECORD_LEN = 256 * 1024 * 1024  # anything bigger is a corrupted length field


def detect_capture_format(path: Path) -> CaptureFormat:
    """Identify the format by magic bytes, or raise a typed error."""
    path = Path(path)
    if not path.is_file():
        raise CaptureError(f"Capture file not found: {path}")
    with path.open("rb") as fh:
        head = fh.read(_PCAP_GLOBAL_HEADER)
    if len(head) < 4:
        raise CorruptCaptureError(f"'{path.name}' is empty or too small to be a capture file")
    magic = head[:4]
    if magic in _PCAP_MAGIC:
        if len(head) < _PCAP_GLOBAL_HEADER:
            raise CorruptCaptureError(f"'{path.name}' has an incomplete pcap global header")
        return _PCAP_MAGIC[magic][0]
    if magic == _PCAPNG_MAGIC:
        if len(head) < 12:
            raise CorruptCaptureError(f"'{path.name}' has an incomplete pcapng section header")
        return CaptureFormat.PCAPNG
    raise UnsupportedFormatError(
        f"'{path.name}' is not a pcap/pcapng file (unrecognized magic bytes {magic.hex()})"
    )


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    format: CaptureFormat
    complete_records: int
    truncated: bool
    detail: str = ""


def scan_integrity(path: Path) -> IntegrityReport:
    """Count complete packet records and detect a truncated tail."""
    path = Path(path)
    fmt = detect_capture_format(path)
    if fmt is CaptureFormat.PCAPNG:
        return _scan_pcapng(path)
    return _scan_pcap(path, fmt)


def _scan_pcap(path: Path, fmt: CaptureFormat) -> IntegrityReport:
    size = path.stat().st_size
    with path.open("rb") as fh:
        order = _PCAP_MAGIC[fh.read(4)][1]
        fh.seek(_PCAP_GLOBAL_HEADER)
        offset, count = _PCAP_GLOBAL_HEADER, 0
        while offset < size:
            header = fh.read(_PCAP_RECORD_HEADER)
            if len(header) < _PCAP_RECORD_HEADER:
                return IntegrityReport(fmt, count, True, f"record header cut short after {count} packets")
            _, _, incl_len, _ = struct.unpack(order + "IIII", header)
            if incl_len > _MAX_RECORD_LEN:
                raise CorruptCaptureError(
                    f"'{path.name}': record {count + 1} declares an impossible length ({incl_len} bytes)"
                )
            offset += _PCAP_RECORD_HEADER + incl_len
            if offset > size:
                return IntegrityReport(fmt, count, True, f"packet {count + 1} is cut short")
            fh.seek(offset)
            count += 1
    return IntegrityReport(fmt, count, False)


def _scan_pcapng(path: Path) -> IntegrityReport:
    size = path.stat().st_size
    fmt = CaptureFormat.PCAPNG
    order = "<"
    offset, count = 0, 0
    with path.open("rb") as fh:
        while offset < size:
            fh.seek(offset)
            head = fh.read(12)
            if len(head) < 8:
                return IntegrityReport(fmt, count, True, f"block header cut short after {count} packets")
            if head[:4] == _PCAPNG_MAGIC:
                # Each Section Header Block declares the byte order for its section.
                if len(head) < 12:
                    return IntegrityReport(fmt, count, True, "section header cut short")
                order = "<" if struct.unpack("<I", head[8:12])[0] == _PCAPNG_BOM else ">"
            block_type, block_len = struct.unpack(order + "II", head[:8])
            if block_len < 12 or block_len % 4 or block_len > _MAX_RECORD_LEN:
                raise CorruptCaptureError(
                    f"'{path.name}': invalid pcapng block length {block_len} at offset {offset}"
                )
            if offset + block_len > size:
                return IntegrityReport(fmt, count, True, f"packet block {count + 1} is cut short")
            if block_type in _PCAPNG_PACKET_BLOCKS:
                count += 1
            offset += block_len
    return IntegrityReport(fmt, count, False)

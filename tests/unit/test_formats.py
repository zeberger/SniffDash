"""Unit tests for magic-byte detection and integrity scanning.

Files are handcrafted byte-by-byte with ``struct`` so each test controls exactly
which structural property is broken.
"""

from __future__ import annotations

import struct

import pytest

from sniffdash.domain.errors import CaptureError, CorruptCaptureError, UnsupportedFormatError
from sniffdash.parsing.formats import CaptureFormat, detect_capture_format, scan_integrity


def pcap_bytes(records: list[bytes], magic: int = 0xA1B2C3D4, order: str = "<") -> bytes:
    """Classic pcap: 24-byte global header + (16-byte record header + data) per packet."""
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for i, data in enumerate(records):
        out += struct.pack(order + "IIII", i, 0, len(data), len(data)) + data
    return out


def pcapng_bytes(n_packets: int) -> bytes:
    """Minimal pcapng: Section Header Block, Interface Description Block, n Enhanced Packet Blocks."""
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    data = b"\x00" * 60
    epb_body = struct.pack("<IIIII", 0, 0, 0, len(data), len(data)) + data
    epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
    return shb + idb + epb * n_packets


@pytest.fixture
def write(tmp_path):
    def _write(name: str, content: bytes):
        path = tmp_path / name
        path.write_bytes(content)
        return path
    return _write


class TestDetectFormat:
    @pytest.mark.parametrize("magic, order, expected", [
        (0xA1B2C3D4, "<", CaptureFormat.PCAP),     # little-endian microsecond
        (0xA1B2C3D4, ">", CaptureFormat.PCAP),     # big-endian microsecond
        (0xA1B23C4D, "<", CaptureFormat.PCAP_NS),  # nanosecond variant
    ])
    def test_pcap_variants(self, write, magic, order, expected):
        assert detect_capture_format(write("a.pcap", pcap_bytes([], magic, order))) is expected

    def test_pcapng(self, write):
        assert detect_capture_format(write("a.pcapng", pcapng_bytes(1))) is CaptureFormat.PCAPNG

    def test_detection_ignores_extension(self, write):
        # A pcapng renamed to .pcap (common!) is still recognized.
        assert detect_capture_format(write("wrong.pcap", pcapng_bytes(1))) is CaptureFormat.PCAPNG

    def test_missing_file(self, tmp_path):
        with pytest.raises(CaptureError, match="not found"):
            detect_capture_format(tmp_path / "nope.pcap")

    def test_empty_file(self, write):
        with pytest.raises(CorruptCaptureError, match="empty"):
            detect_capture_format(write("e.pcap", b""))

    def test_incomplete_global_header(self, write):
        with pytest.raises(CorruptCaptureError, match="incomplete"):
            detect_capture_format(write("h.pcap", pcap_bytes([])[:10]))

    def test_garbage(self, write):
        with pytest.raises(UnsupportedFormatError, match="magic"):
            detect_capture_format(write("g.pcap", b"PK\x03\x04 this is a zip file"))


class TestScanIntegrity:
    def test_complete_pcap(self, write):
        report = scan_integrity(write("ok.pcap", pcap_bytes([b"a" * 60, b"b" * 70])))
        assert (report.complete_records, report.truncated) == (2, False)

    def test_pcap_cut_inside_packet_data(self, write):
        report = scan_integrity(write("cut.pcap", pcap_bytes([b"a" * 60, b"b" * 70])[:-5]))
        assert report.truncated and report.complete_records == 1

    def test_pcap_cut_inside_record_header(self, write):
        data = pcap_bytes([b"a" * 60]) + b"\x00" * 7  # 7 stray bytes: half a record header
        report = scan_integrity(write("cut2.pcap", data))
        assert report.truncated and report.complete_records == 1

    def test_impossible_record_length_is_corrupt(self, write):
        bad = pcap_bytes([]) + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        with pytest.raises(CorruptCaptureError, match="impossible length"):
            scan_integrity(write("bad.pcap", bad))

    def test_complete_pcapng_counts_only_packet_blocks(self, write):
        report = scan_integrity(write("ok.pcapng", pcapng_bytes(3)))
        assert (report.complete_records, report.truncated) == (3, False)  # SHB/IDB not counted

    def test_truncated_pcapng(self, write):
        report = scan_integrity(write("cut.pcapng", pcapng_bytes(3)[:-20]))
        assert report.truncated and report.complete_records == 2

    def test_invalid_pcapng_block_length(self, write):
        data = pcapng_bytes(0) + struct.pack("<II", 6, 7) + b"\x00" * 8  # length 7: not a multiple of 4
        with pytest.raises(CorruptCaptureError, match="block length"):
            scan_integrity(write("bad.pcapng", data))

"""Unit tests for InMemoryFrameRepository, built from hand-made Frames."""

from __future__ import annotations

import pytest

from sniffdash.domain.errors import DuplicateFrameError, FrameNotFoundError
from sniffdash.domain.models import Endpoint, Frame, Transport
from sniffdash.repository import FRAME_COLUMNS, InMemoryFrameRepository


def frame(n: int, ts: float, protocols=("eth", "ip", "tcp"), stream: int | None = 0,
          transport: Transport | None = Transport.TCP) -> Frame:
    return Frame(number=n, timestamp=ts, length=100 + n, protocols=protocols,
                 highest_protocol=protocols[-1], src=Endpoint("10.0.0.1", 1000 + n),
                 dst=Endpoint("10.0.0.2", 80), transport=transport, stream_id=stream)


@pytest.fixture
def repo() -> InMemoryFrameRepository:
    # Inserted OUT of order, and frame 3 has an EARLIER timestamp than frame 2
    # (this happens in real captures from multi-queue NICs).
    return InMemoryFrameRepository([
        frame(3, 10.5, ("eth", "ip", "udp", "dns"), stream=0, transport=Transport.UDP),
        frame(1, 10.0),
        frame(2, 11.0, ("eth", "ip", "tcp", "http")),
        frame(4, 12.0, ("eth", "arp"), stream=None, transport=None),
    ])


def test_len_contains_get(repo):
    assert len(repo) == 4
    assert 2 in repo and 99 not in repo
    assert repo.get(2).highest_protocol == "http"
    assert repo.get(99) is None


def test_require_raises_typed_error(repo):
    with pytest.raises(FrameNotFoundError, match="Frame 42"):
        repo.require(42)


def test_iter_is_in_frame_number_order(repo):
    assert [f.number for f in repo.iter()] == [1, 2, 3, 4]


def test_iter_by_protocol(repo):
    assert [f.number for f in repo.iter("tcp")] == [1, 2]
    assert [f.number for f in repo.iter("HTTP")] == [2]  # case-insensitive
    assert list(repo.iter("quic")) == []


def test_streams_are_separated_by_transport(repo):
    # TCP stream 0 and UDP stream 0 are DIFFERENT conversations.
    assert [f.number for f in repo.by_stream(Transport.TCP, 0)] == [1, 2]
    assert [f.number for f in repo.by_stream(Transport.UDP, 0)] == [3]


def test_time_range_uses_min_max_not_first_last(repo):
    assert repo.time_range() == (10.0, 12.0)


def test_protocols(repo):
    assert repo.protocols() == {"eth", "ip", "tcp", "udp", "dns", "http", "arp"}


def test_get_many_skips_missing(repo):
    assert [f.number for f in repo.get_many([4, 99, 1])] == [4, 1]


def test_duplicate_frame_numbers_rejected():
    with pytest.raises(DuplicateFrameError):
        InMemoryFrameRepository([frame(1, 0.0), frame(1, 1.0)])


def test_dataframe_shape_and_types(repo):
    df = repo.to_dataframe()
    assert tuple(df.columns) == FRAME_COLUMNS
    assert df["number"].tolist() == [1, 2, 3, 4]
    assert str(df["time"].dt.tz) == "UTC"
    assert df.loc[df["number"] == 4, "src_port"].iloc[0] == 1004
    assert df["stream_id"].isna().sum() == 1  # ARP frame: nullable Int64, not float NaN


def test_dataframe_copies_are_isolated(repo):
    df = repo.to_dataframe()
    df["length"] = 0
    assert repo.to_dataframe()["length"].sum() > 0  # cached original untouched


def test_empty_repository():
    empty = InMemoryFrameRepository([])
    assert len(empty) == 0 and empty.time_range() is None
    assert empty.to_dataframe().empty
    assert tuple(empty.to_dataframe().columns) == FRAME_COLUMNS

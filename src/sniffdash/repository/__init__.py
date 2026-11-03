"""Repository layer: read-only, indexed access to parsed frames."""

from sniffdash.repository.base import FrameRepository
from sniffdash.repository.in_memory import FRAME_COLUMNS, InMemoryFrameRepository

__all__ = ["FRAME_COLUMNS", "FrameRepository", "InMemoryFrameRepository"]

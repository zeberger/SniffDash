"""Domain layer: pure data models, result containers and the error hierarchy.

This package imports nothing outside the standard library. Every other layer
depends on it; it depends on nobody (Dependency Inversion's "stable core").
"""

from sniffdash.domain.errors import (
    AnalysisError,
    CaptureError,
    CorruptCaptureError,
    DuplicateFrameError,
    FrameNotFoundError,
    IssueSeverity,
    LLMAuthError,
    LLMContextOverflowError,
    LLMError,
    LLMRateLimitError,
    LLMResponseFormatError,
    ParseIssue,
    ParserUnavailableError,
    RepositoryError,
    SniffDashError,
    UnsupportedFormatError,
)
from sniffdash.domain.models import (
    Endpoint,
    Frame,
    FrozenMap,
    HttpMessage,
    HttpRequest,
    HttpResponse,
    HttpTransaction,
    StatusClass,
    Transport,
)
from sniffdash.domain.results import (
    AnalysisReport,
    AnalysisResult,
    CaptureSummary,
    HttpAnalysisResult,
    ParseOutcome,
)

__all__ = [
    "AnalysisError", "AnalysisReport", "AnalysisResult", "CaptureError", "CaptureSummary",
    "CorruptCaptureError", "DuplicateFrameError", "Endpoint", "Frame", "FrameNotFoundError",
    "FrozenMap", "HttpAnalysisResult", "HttpMessage", "HttpRequest", "HttpResponse",
    "HttpTransaction", "IssueSeverity", "LLMAuthError", "LLMContextOverflowError", "LLMError",
    "LLMRateLimitError", "LLMResponseFormatError", "ParseIssue", "ParseOutcome",
    "ParserUnavailableError", "RepositoryError", "SniffDashError", "StatusClass", "Transport",
    "UnsupportedFormatError",
]

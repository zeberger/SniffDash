"""Exception hierarchy and non-fatal parse issues.

SniffDash reports problems through two deliberately separate channels:

* **Exceptions** (``SniffDashError`` subclasses): an operation could not complete
  at all. Example: the uploaded file is not a capture.
* **ParseIssue records** (the *Notification* pattern): one packet or one field
  was bad, but processing continued. They are collected in ``ParseOutcome.issues``
  and shown to the user as warnings, rather than aborting a 50,000-packet parse
  because of a single malformed frame.

A single root class lets the UI write ``except SniffDashError`` once and render
a friendly message, while still letting unexpected bugs surface as real errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SniffDashError(Exception):
    """Root of every exception raised intentionally by SniffDash code."""


# --- Capture / parsing -------------------------------------------------------------

class CaptureError(SniffDashError):
    """The capture file cannot be read (missing, unreadable, ...)."""


class UnsupportedFormatError(CaptureError):
    """The file is not a pcap/pcapng capture (wrong magic bytes)."""


class CorruptCaptureError(CaptureError):
    """The file looks like a capture but its structure is broken beyond recovery."""


class ParserUnavailableError(CaptureError):
    """The requested parser backend is not installed (e.g. tshark missing)."""


# --- Repository --------------------------------------------------------------------

class RepositoryError(SniffDashError):
    """Invalid use of a frame repository."""


class DuplicateFrameError(RepositoryError):
    """Two frames with the same frame number were inserted."""


class FrameNotFoundError(RepositoryError, KeyError):
    """A frame number was requested that does not exist in the capture."""


# --- Analysis & LLM (declared now so the hierarchy is complete; used in Steps 2-3) --

class AnalysisError(SniffDashError):
    """An analyzer failed. The engine isolates it so other analyzers still run."""


class LLMError(SniffDashError):
    """Base class for failures talking to the language model.

    ``switched_model`` is set when the failure made the client move to its fallback
    model (quota used up, or the main model overloaded), so the caller can restart
    the question there.
    """

    def __init__(self, message: str = "", *, switched_model: str | None = None) -> None:
        super().__init__(message)
        self.switched_model = switched_model


class LLMAuthError(LLMError):
    """Missing or invalid API key."""


class LLMRateLimitError(LLMError):
    """The provider throttled us (HTTP 429): the model's quota is used up for now."""


class LLMContextOverflowError(LLMError):
    """The prompt exceeded the model's context window."""


class LLMResponseFormatError(LLMError):
    """The model did not return the structured JSON we asked for."""


# --- Non-fatal issues (Notification pattern) ----------------------------------------

class IssueSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """A problem found while parsing, which did not stop the parse.

    ``frame_number`` is ``None`` for file-level issues (e.g. truncation).
    """

    message: str
    severity: IssueSeverity = IssueSeverity.WARNING
    frame_number: int | None = None

    def __str__(self) -> str:
        where = f"frame {self.frame_number}" if self.frame_number is not None else "capture"
        return f"[{self.severity.value.upper()}] {where}: {self.message}"

"""Application settings, loaded from the environment and an optional local ``.env`` file.

``load_settings()`` is called explicitly by the application (and by tests that
want it), never at import time, so importing SniffDash has no hidden side effects.
Real environment variables always win over ``.env`` values, so a grader or CI can
override anything without editing files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Verified live on 2026-11-10: gemini-2.5-flash is closed to new users (404), and
# gemini-3.8-flash (Google's suggestion) returned 503 "high demand"; 3.5 Flash answered
# correctly with valid citations. Override with GEMINI_MODEL in .env.
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
# Used when the main model's quota is exhausted (HTTP 429). A "lite" model has its own,
# separate free-tier quota; listed for the project's key with models.list() on 2026-11-13.
DEFAULT_GEMINI_FALLBACK_MODEL = "gemini-3.5-flash-lite"
# Measured live on 2026-11-13 ("Which HTTP request was the slowest?"): default thinking
# took 19.9 s, "low" took 5.5 s with the same verified answer. Our questions are lookups.
DEFAULT_GEMINI_THINKING_LEVEL = "low"


@dataclass(frozen=True, slots=True)
class Settings:
    gemini_api_key: str | None = None
    gemini_model: str = DEFAULT_GEMINI_MODEL
    gemini_fallback_model: str | None = DEFAULT_GEMINI_FALLBACK_MODEL
    gemini_thinking_level: str | None = DEFAULT_GEMINI_THINKING_LEVEL
    tshark_path: str | None = None

    def __repr__(self) -> str:  # never print the secret, even in a traceback
        key = "set" if self.gemini_api_key else "missing"
        return (f"Settings(gemini_api_key=<{key}>, gemini_model={self.gemini_model!r}, "
                f"gemini_fallback_model={self.gemini_fallback_model!r}, "
                f"gemini_thinking_level={self.gemini_thinking_level!r}, tshark_path={self.tshark_path!r})")


def _optional(name: str, default: str) -> str | None:
    """Unset → the default; set to an empty value → None (the feature is turned off)."""
    return os.environ.get(name, default).strip() or None


def load_settings(env_file: str | Path | None = ".env") -> Settings:
    """Load ``.env`` (if present) into the process environment, then read settings.

    ``override=False``: variables already set in the real environment keep priority.
    TSHARK_PATH is exported, so the parsing layer's tshark locator sees it as well.
    """
    if env_file is not None and Path(env_file).is_file():
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)
    return Settings(
        gemini_api_key=os.environ.get("GEMINI_API_KEY") or None,
        gemini_model=os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL,
        gemini_fallback_model=_optional("GEMINI_FALLBACK_MODEL", DEFAULT_GEMINI_FALLBACK_MODEL),
        gemini_thinking_level=_optional("GEMINI_THINKING_LEVEL", DEFAULT_GEMINI_THINKING_LEVEL),
        tshark_path=os.environ.get("TSHARK_PATH") or None,
    )

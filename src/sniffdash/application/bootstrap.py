"""Composition root: builds the long-lived services once, from settings.

The UI asks for ``AppServices`` and never constructs clients or factories itself.
A missing API key is not an error here: the dashboard still works, and the
Ask AI tab shows ``llm_unavailable_reason`` with setup instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sniffdash.config import Settings, load_settings
from sniffdash.domain.errors import LLMError
from sniffdash.llm.client import GeminiClient
from sniffdash.llm.service import LLMService
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.factory import ParserFactory


@dataclass(frozen=True)
class AppServices:
    settings: Settings
    llm: LLMService | None
    llm_unavailable_reason: str | None
    available_backends: tuple[Backend, ...]


def build_services(env_file: str | Path | None = ".env") -> AppServices:
    settings = load_settings(env_file)
    try:
        llm, reason = LLMService(GeminiClient(settings)), None
    except LLMError as exc:  # e.g. GEMINI_API_KEY missing
        llm, reason = None, str(exc)
    return AppServices(settings=settings, llm=llm, llm_unavailable_reason=reason,
                       available_backends=tuple(ParserFactory.default().available_backends()))

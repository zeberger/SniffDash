"""Versioned prompt templates, shipped as package data.

The system prompt is ONE shared rules file plus ONE style file per skill level.
The level changes how things are explained, never the grounding and evidence
rules, which are byte-identical for every level.
"""

from __future__ import annotations

from importlib.resources import files

from sniffdash.llm.answer import SkillLevel

PROMPT_VERSION = "system_v1"
_STYLE_SLOT = "{explanation_style}"


def _read(*parts: str) -> str:
    return files(__name__).joinpath(*parts).read_text(encoding="utf-8")


def build_system_prompt(level: SkillLevel) -> str:
    base = _read(f"{PROMPT_VERSION}.md")
    return base.replace(_STYLE_SLOT, _read("levels", f"{level.value}.md").strip())

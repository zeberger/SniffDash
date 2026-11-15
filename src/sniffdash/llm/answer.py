"""Answer contract between the model and SniffDash.

The model never returns free text. It must call the ``submit_answer`` function,
whose arguments follow ``ANSWER_SCHEMA``: an answer, evidence items
(frame number + timestamp + claim) and an ``insufficient_data`` flag. Every
timestamp crossing this boundary uses ONE format, ISO-8601 UTC with milliseconds,
so the citation validator can compare it exactly with the capture.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

SUBMIT_ANSWER = "submit_answer"


class SkillLevel(StrEnum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"

    @classmethod
    def parse(cls, value: SkillLevel | str) -> SkillLevel:
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            options = ", ".join(level.value for level in cls)
            raise ValueError(f"Unknown skill level {value!r}; choose one of: {options}") from None


def format_ts(epoch: float) -> str:
    """1700000000.15 → '2023-11-14T22:13:20.150Z'."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(text: str) -> float:
    return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).timestamp()


ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "answer": {"type": "string", "description": "The answer, in the language of the question."},
        "evidence": {
            "type": "array",
            "description": "One item per factual claim, copied from the capture context or tool results.",
            "items": {
                "type": "object",
                "properties": {
                    "frame_number": {"type": "integer", "description": "Wireshark frame number."},
                    "timestamp": {"type": "string", "description": "That frame's ISO-8601 UTC timestamp, exactly as given."},
                    "claim": {"type": "string", "description": "What this frame proves."},
                },
                "required": ["frame_number", "timestamp", "claim"],
            },
        },
        "insufficient_data": {"type": "boolean", "description": "True when the capture cannot answer the question."},
    },
    "required": ["answer", "evidence", "insufficient_data"],
}


@dataclass(frozen=True, slots=True)
class Evidence:
    frame_number: int
    timestamp: str
    claim: str


@dataclass(frozen=True, slots=True)
class GroundedAnswer:
    answer: str
    evidence: tuple[Evidence, ...] = ()
    insufficient_data: bool = False

    @classmethod
    def from_args(cls, args: Mapping[str, Any]) -> GroundedAnswer:
        """Validate ``submit_answer`` arguments; ValueError messages are fed back to the model."""
        if not isinstance(args.get("answer"), str) or not args["answer"].strip():
            raise ValueError("'answer' must be a non-empty string")
        if not isinstance(args.get("insufficient_data"), bool):
            raise ValueError("'insufficient_data' must be true or false")
        raw = args.get("evidence")
        if not isinstance(raw, (list, tuple)):
            raise ValueError("'evidence' must be a list")
        items = []
        for i, item in enumerate(raw):
            try:
                items.append(Evidence(int(item["frame_number"]), str(item["timestamp"]), str(item["claim"])))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"evidence[{i}] needs integer frame_number, timestamp and claim ({exc})") from exc
        return cls(args["answer"].strip(), tuple(items), args["insufficient_data"])


@dataclass(frozen=True, slots=True)
class CitationIssue:
    frame_number: int
    reason: str


@dataclass(frozen=True, slots=True)
class ValidatedAnswer:
    """What the UI shows: the answer, the evidence that checked out, and what didn't."""

    answer: str
    valid_evidence: tuple[Evidence, ...]
    invalid_citations: tuple[CitationIssue, ...]
    insufficient_data: bool
    skill_level: SkillLevel
    tools_used: tuple[str, ...] = field(default=())
    model: str | None = None  # which model answered (the fallback, when the main quota ran out)

    @property
    def fully_grounded(self) -> bool:
        return not self.invalid_citations and (bool(self.valid_evidence) or self.insufficient_data)

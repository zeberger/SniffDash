"""CitationValidator: checks every frame the model cites against the capture (Req 34).

A language model can produce a plausible frame number that doesn't exist, or the
right frame with the wrong time. This turns "the model said so" into "the capture
confirms it":

* evidence item → the frame must exist AND its timestamp must match within 1 ms;
* frame numbers mentioned in the answer text ("frame 42", "frames 4 and 5",
  "פריים 7") must exist, so a number can't bypass the evidence list.

Invalid citations are reported, never silently dropped, so the UI can warn the user.
"""

from __future__ import annotations

import re

from sniffdash.llm.answer import (
    CitationIssue, Evidence, GroundedAnswer, SkillLevel, ValidatedAnswer, parse_ts,
)
from sniffdash.repository.base import FrameRepository

TIMESTAMP_TOLERANCE_S = 0.001

# "frame 4", "frames 4, 5 and 7", "frame #12", plus the Hebrew forms (פריים / פריימים / מסגרת / מסגרות).
_MENTION = re.compile(
    r"(?:\bframes?\b|פריימים|פריים|מסגרות|מסגרת)\s*#?\s*(\d+(?:\s*(?:,|and|&|or|-|–|ו-?)\s*#?\d+)*)",
    re.IGNORECASE,
)


def mentioned_frames(text: str) -> list[int]:
    numbers: list[int] = []
    for match in _MENTION.finditer(text):
        numbers += [int(n) for n in re.findall(r"\d+", match.group(1))]
    return list(dict.fromkeys(numbers))  # de-duplicated, order kept


class CitationValidator:
    def __init__(self, repo: FrameRepository) -> None:
        self._repo = repo

    def check(self, item: Evidence) -> CitationIssue | None:
        frame = self._repo.get(item.frame_number)
        if frame is None:
            return CitationIssue(item.frame_number, "frame does not exist in this capture")
        try:
            cited = parse_ts(item.timestamp)
        except ValueError:
            return CitationIssue(item.frame_number, f"unreadable timestamp {item.timestamp!r}")
        if abs(cited - frame.timestamp) > TIMESTAMP_TOLERANCE_S:
            return CitationIssue(item.frame_number,
                                 f"timestamp {item.timestamp} does not match the frame's actual time")
        return None

    def validate(self, answer: GroundedAnswer, skill_level: SkillLevel = SkillLevel.INTERMEDIATE,
                 tools_used: tuple[str, ...] = ()) -> ValidatedAnswer:
        valid: list[Evidence] = []
        issues: list[CitationIssue] = []
        for item in answer.evidence:
            issue = self.check(item)
            (issues.append(issue) if issue else valid.append(item))
        for number in mentioned_frames(answer.answer):
            if number not in self._repo:
                issues.append(CitationIssue(number, "frame mentioned in the answer does not exist"))
        return ValidatedAnswer(answer=answer.answer, valid_evidence=tuple(valid),
                               invalid_citations=tuple(issues), insufficient_data=answer.insufficient_data,
                               skill_level=skill_level, tools_used=tools_used)

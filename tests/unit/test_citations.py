"""Unit tests for answer parsing and citation validation (AC3, AC4)."""

from __future__ import annotations

import pytest

from sniffdash.domain.models import Frame
from sniffdash.llm.answer import (
    Evidence, GroundedAnswer, SkillLevel, format_ts, parse_ts,
)
from sniffdash.llm.citations import CitationValidator, mentioned_frames
from sniffdash.repository import InMemoryFrameRepository

T4, T5 = 1_700_000_000.030, 1_700_000_000.150


@pytest.fixture
def validator():
    repo = InMemoryFrameRepository([Frame(number=4, timestamp=T4, length=1),
                                    Frame(number=5, timestamp=T5, length=1)])
    return CitationValidator(repo)


def answer(text="ok", *evidence, insufficient=False):
    return GroundedAnswer(text, tuple(evidence), insufficient)


class TestTimestamps:
    def test_round_trip_keeps_milliseconds(self):
        assert format_ts(T5) == "2023-11-14T22:13:20.150Z"
        assert parse_ts(format_ts(T5)) == pytest.approx(T5, abs=1e-6)


class TestValidation:
    def test_valid_citation(self, validator):
        result = validator.validate(answer("slow", Evidence(5, format_ts(T5), "response")))
        assert len(result.valid_evidence) == 1 and result.invalid_citations == () and result.fully_grounded

    def test_frame_that_does_not_exist(self, validator):
        result = validator.validate(answer("x", Evidence(99, format_ts(T5), "made up")))
        assert result.invalid_citations[0].frame_number == 99 and not result.fully_grounded

    def test_right_frame_wrong_time(self, validator):
        issue, = validator.validate(answer("x", Evidence(5, format_ts(T4), "wrong time"))).invalid_citations
        assert "does not match" in issue.reason

    def test_unreadable_timestamp(self, validator):
        issue, = validator.validate(answer("x", Evidence(5, "yesterday", "?"))).invalid_citations
        assert "unreadable" in issue.reason

    def test_frame_number_hidden_in_the_text_is_checked(self, validator):
        # Evidence is fine, but the prose claims frame 42, which doesn't exist.
        result = validator.validate(answer("See frames 5 and 42.", Evidence(5, format_ts(T5), "ok")))
        assert [i.frame_number for i in result.invalid_citations] == [42]

    def test_insufficient_data_without_evidence_is_grounded(self, validator):
        result = validator.validate(answer("The capture has no DNS traffic.", insufficient=True))
        assert result.fully_grounded

    def test_answer_without_evidence_is_not_grounded(self, validator):
        assert not validator.validate(answer("Trust me.")).fully_grounded


class TestMentions:
    @pytest.mark.parametrize("text, expected", [
        ("frame 4", [4]), ("Frames 4, 5 and 7", [4, 5, 7]), ("frame #12", [12]),
        ("between frames 4-5", [4, 5]), ("הבקשה בפריים 4 והתשובה בפריים 5", [4, 5]),
        ("no numbers here, 200 OK", []),
    ])
    def test_mentioned_frames(self, text, expected):
        assert mentioned_frames(text) == expected


class TestAnswerParsing:
    def test_from_args(self):
        parsed = GroundedAnswer.from_args({"answer": " hi ", "insufficient_data": False,
                                           "evidence": [{"frame_number": "5", "timestamp": "t", "claim": "c"}]})
        assert parsed.answer == "hi" and parsed.evidence == (Evidence(5, "t", "c"),)

    @pytest.mark.parametrize("args, message", [
        ({"answer": "", "evidence": [], "insufficient_data": False}, "answer"),
        ({"answer": "a", "evidence": [], "insufficient_data": "no"}, "insufficient_data"),
        ({"answer": "a", "evidence": "frame 5", "insufficient_data": False}, "list"),
        ({"answer": "a", "evidence": [{"frame_number": "x"}], "insufficient_data": False}, r"evidence\[0\]"),
    ])
    def test_invalid_args_explain_the_problem(self, args, message):
        with pytest.raises(ValueError, match=message):
            GroundedAnswer.from_args(args)


@pytest.mark.parametrize("raw, expected", [("Beginner", SkillLevel.BEGINNER), ("EXPERT ", SkillLevel.EXPERT)])
def test_skill_level_parsing(raw, expected):
    assert SkillLevel.parse(raw) is expected


def test_unknown_skill_level_lists_the_options():
    with pytest.raises(ValueError, match="beginner, intermediate, expert"):
        SkillLevel.parse("guru")

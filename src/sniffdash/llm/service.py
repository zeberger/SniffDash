"""LLMService: the natural-language query entry point (Reqs 31–34).

    ask(question, report, repo, skill_level) → ValidatedAnswer

One question runs a short conversation:
  1. the user turn = capture context (JSON) + the question;
  2. the model calls query tools; our code runs them and returns the results;
  3. repeat (at most ``max_tool_rounds``) until the model calls ``submit_answer``;
  4. the answer's arguments are schema-checked (one repair turn allowed), then
     every citation is verified against the capture.

If the main model's quota runs out (or it stays overloaded) mid-question and the
client switches to its fallback model, the question restarts once from step 1 there.

The model never computes or remembers facts on its own: tools compute, the
validator checks, and the model explains.
"""

from __future__ import annotations

from dataclasses import replace

from sniffdash.domain.errors import LLMError, LLMResponseFormatError
from sniffdash.domain.results import AnalysisReport
from sniffdash.llm.answer import ANSWER_SCHEMA, SUBMIT_ANSWER, GroundedAnswer, SkillLevel, ValidatedAnswer
from sniffdash.llm.citations import CitationValidator
from sniffdash.llm.client import LLMClient, LLMReply, ToolResult, Turn
from sniffdash.llm.context import ContextBuilder
from sniffdash.llm.prompts import build_system_prompt
from sniffdash.llm.tools import ToolBox, ToolContext
from sniffdash.repository.base import FrameRepository

SUBMIT_DECLARATION = {
    "name": SUBMIT_ANSWER,
    "description": "Deliver the final answer with its evidence. Call exactly once, as the last step.",
    "parameters": ANSWER_SCHEMA,
}


class LLMService:
    def __init__(self, client: LLMClient, context_builder: ContextBuilder | None = None,
                 tools: ToolBox | None = None, max_tool_rounds: int = 4) -> None:
        self._client = client
        self._context = context_builder or ContextBuilder()
        self._tools = tools or ToolBox.default()
        self._max_tool_rounds = max_tool_rounds

    def ask(self, question: str, report: AnalysisReport, repo: FrameRepository, *,
            skill_level: SkillLevel | str = SkillLevel.INTERMEDIATE) -> ValidatedAnswer:
        question = (question or "").strip()
        if not question:
            raise ValueError("Please enter a question.")
        level = SkillLevel.parse(skill_level)

        system = build_system_prompt(level)
        declarations = [*self._tools.declarations(), SUBMIT_DECLARATION]
        tool_ctx = ToolContext(report, repo)
        context_json = ContextBuilder.render(self._context.build(report))
        first = Turn("user", text=f"CAPTURE CONTEXT (JSON):\n{context_json}\n\nQUESTION:\n{question}")
        try:
            answer = self._converse(system, declarations, first, tool_ctx, repo, level)
        except LLMError as exc:
            if not exc.switched_model:
                raise
            # The main model's quota ran out or it is overloaded, and the client moved to its fallback
            # model. Restart from the first turn: one model's replies (thought signatures) can't be
            # replayed to another.
            answer = self._converse(system, declarations, first, tool_ctx, repo, level)
        return replace(answer, model=getattr(self._client, "active_model", None))

    def _converse(self, system: str, declarations: list[dict], first: Turn, tool_ctx: ToolContext,
                  repo: FrameRepository, level: SkillLevel) -> ValidatedAnswer:
        turns = [first]
        tools_used: list[str] = []
        tool_rounds = 0
        repaired = False
        while True:
            reply = self._client.complete(system, turns, declarations)
            submit = next((c for c in reply.tool_calls if c.name == SUBMIT_ANSWER), None)

            if submit is not None:
                try:
                    answer = GroundedAnswer.from_args(submit.arguments)
                except ValueError as exc:
                    repaired = self._repair_once(repaired, exc)
                    turns += [self._model_turn(reply), Turn("tool", tool_results=(ToolResult(
                        SUBMIT_ANSWER, {"error": f"Invalid answer: {exc}. Call submit_answer again, correctly."},
                        submit.call_id),))]
                    continue
                return CitationValidator(repo).validate(answer, level, tuple(tools_used))

            if not reply.tool_calls:  # plain text instead of a function call
                repaired = self._repair_once(repaired, "the reply was text, not a submit_answer call")
                turns += [self._model_turn(reply),
                          Turn("user", text="Deliver your answer by calling submit_answer.")]
                continue

            tool_rounds += 1
            if tool_rounds > self._max_tool_rounds:
                raise LLMError(f"The model did not finish within {self._max_tool_rounds} tool rounds.")
            results = tuple(ToolResult(c.name, self._tools.run(c.name, c.arguments, tool_ctx), c.call_id)
                            for c in reply.tool_calls)
            tools_used += [c.name for c in reply.tool_calls]
            turns += [self._model_turn(reply), Turn("tool", tool_results=results)]

    @staticmethod
    def _model_turn(reply: LLMReply) -> Turn:
        return Turn("model", text=reply.text, tool_calls=reply.tool_calls, raw=reply.raw)

    @staticmethod
    def _repair_once(already_repaired: bool, problem: object) -> bool:
        if already_repaired:
            raise LLMResponseFormatError(f"The model did not produce a valid answer: {problem}")
        return True

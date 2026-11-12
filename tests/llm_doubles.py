"""LLM test doubles shared by unit, integration and UI tests (no network, no key)."""

from __future__ import annotations


class ScriptedClient:
    """A fake LLMClient that plays back pre-written replies, one per model call.

    Each script step is either an LLMReply, or a callable(turns) -> LLMReply that can
    read earlier tool results (e.g. copy the timestamp a tool returned into its
    evidence, exactly as a well-behaved model would). Records every call it receives.
    """

    def __init__(self, *steps):
        self.steps, self.calls = list(steps), []

    def complete(self, system, turns, tools):
        self.calls.append({"system": system, "turns": list(turns), "tools": list(tools)})
        step = self.steps.pop(0)
        return step(turns) if callable(step) else step


def call(name, call_id=None, **arguments):
    from sniffdash.llm.client import LLMReply, ToolCall
    return LLMReply(text=None, tool_calls=(ToolCall(name, arguments, call_id),))


def last_tool_result(turns, name):
    """The content of the most recent tool result called `name`."""
    for turn in reversed(turns):
        for result in turn.tool_results:
            if result.name == name:
                return result.content
    raise AssertionError(f"no result for {name}")

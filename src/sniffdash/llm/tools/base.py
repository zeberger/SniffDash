"""QueryTool (Command) + ToolRegistry: deterministic functions the model can call.

The model decides WHICH question to ask; our code computes the ANSWER. Every tool
returns plain JSON whose rows carry frame numbers and ISO timestamps, so the model
can cite them and ``CitationValidator`` can check them.

Tools never raise into the conversation: bad arguments or missing data become
``{"error": "..."}``, which the model reads and can recover from.

Parameter schemas use only the JSON-Schema subset every Gemini model accepts
(type / properties / required / items / enum / description).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, TypeVar

from sniffdash.domain.results import AnalysisReport
from sniffdash.plugins import LazyDiscovery
from sniffdash.repository.base import FrameRepository


@dataclass(frozen=True, slots=True)
class ToolContext:
    report: AnalysisReport
    repo: FrameRepository


class ToolArgumentError(ValueError):
    """Raised by a tool for bad arguments; reported back to the model as an error."""


class QueryTool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    parameters: ClassVar[dict[str, Any]] = {"type": "object", "properties": {}}

    @abstractmethod
    def run(self, args: Mapping[str, Any], ctx: ToolContext) -> dict[str, Any]:
        """Compute the result. Raise ToolArgumentError for bad input."""

    def declaration(self) -> dict[str, Any]:
        """Provider-neutral function declaration (the LLM adapter converts it)."""
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


T = TypeVar("T", bound=type[QueryTool])


class ToolRegistry:
    def __init__(self, package: str | None = None) -> None:
        self._classes: dict[str, type[QueryTool]] = {}
        self._discovery = LazyDiscovery(package)

    def register(self, cls: T) -> T:
        existing = self._classes.get(cls.name)
        if existing is not None and existing is not cls:
            raise ValueError(f"Duplicate tool name '{cls.name}'")
        self._classes[cls.name] = cls
        return cls

    def create_all(self) -> dict[str, QueryTool]:
        self._discovery.ensure()
        return {name: cls() for name, cls in sorted(self._classes.items())}


class ToolBox:
    """The tools available for one question, plus safe execution."""

    def __init__(self, tools: Mapping[str, QueryTool]) -> None:
        self._tools = dict(tools)

    @classmethod
    def default(cls) -> ToolBox:
        return cls(tool_registry.create_all())

    def declarations(self) -> list[dict[str, Any]]:
        return [tool.declaration() for tool in self._tools.values()]

    def run(self, name: str, args: Mapping[str, Any], ctx: ToolContext) -> dict[str, Any]:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"Unknown tool '{name}'. Available: {', '.join(self._tools)}"}
        try:
            return tool.run(args or {}, ctx)
        except ToolArgumentError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # a tool bug must not end the conversation
            return {"error": f"Tool '{name}' failed: {exc}"}


tool_registry = ToolRegistry("sniffdash.llm.tools")
register_tool: Callable[[T], T] = tool_registry.register

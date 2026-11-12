"""ResultView (Strategy) + ViewRegistry: the dashboard's tabs, discovered automatically.

The layout never lists its tabs. It asks the registry for every view that applies
to the loaded capture and renders them in ``order``. A future DNS analyzer gets
its tab by adding one module to ``sniffdash/ui/views/``, with no layout edit
(Open/Closed, same pattern as the extractor, analyzer and tool registries).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar, TypeVar

from sniffdash.application import AnalysisSession, AppServices
from sniffdash.plugins import LazyDiscovery


@dataclass(frozen=True)
class ViewContext:
    session: AnalysisSession
    services: AppServices
    mode: str = "light"  # "light" | "dark", for chart colors


class ResultView(ABC):
    title: ClassVar[str]
    order: ClassVar[int] = 100

    def applies(self, session: AnalysisSession) -> bool:
        """Whether this tab makes sense for the loaded capture (default: always)."""
        return True

    @abstractmethod
    def render(self, ctx: ViewContext) -> None:
        """Draw the tab's content with Streamlit."""


V = TypeVar("V", bound=type[ResultView])


class ViewRegistry:
    def __init__(self, package: str | None = None) -> None:
        self._classes: list[type[ResultView]] = []
        self._discovery = LazyDiscovery(package)

    def register(self, cls: V) -> V:
        if cls not in self._classes:
            self._classes.append(cls)
        return cls

    def create_all(self) -> list[ResultView]:
        self._discovery.ensure()
        return [cls() for cls in sorted(self._classes, key=lambda c: (c.order, c.title))]


view_registry = ViewRegistry("sniffdash.ui.views")
register_view: Callable[[V], V] = view_registry.register

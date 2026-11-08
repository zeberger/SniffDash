"""Plugin discovery shared by every registry (extractors, analyzers, ...).

A registry's plugins live in one package and register themselves with a
decorator when their module is imported. ``LazyDiscovery`` imports that package's
modules exactly once, on first use, and is safe under concurrency: Streamlit
serves several sessions from worker threads, and a thread must never see a
half-filled registry.
"""

from __future__ import annotations

import importlib
import pkgutil
import threading


def import_submodules(package: str, skip: frozenset[str] = frozenset({"base"})) -> None:
    """Import every direct submodule of ``package`` (except ``skip``) so its decorators run."""
    pkg = importlib.import_module(package)
    for module in pkgutil.iter_modules(pkg.__path__):
        if module.name not in skip:
            importlib.import_module(f"{package}.{module.name}")


class LazyDiscovery:
    """Runs ``import_submodules(package)`` once, thread-safely, on the first ``ensure()``."""

    def __init__(self, package: str | None) -> None:
        self._package = package
        self._done = package is None
        self._lock = threading.Lock()

    def ensure(self) -> None:
        if self._done:  # fast path, no lock once discovery has completed
            return
        with self._lock:
            if self._done:  # another thread finished while we waited
                return
            import_submodules(self._package)
            self._done = True  # only after every import succeeded

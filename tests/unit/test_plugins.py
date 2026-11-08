"""Unit tests for thread-safe plugin discovery (review finding: discovery race).

Before the fix, the "discovered" flag was set BEFORE the imports ran, so a second
Streamlit session arriving mid-import saw a half-filled registry and silently
skipped protocols. The test builds a throwaway plugin package whose import is
deliberately slow, then hits discovery from 8 threads at once.
"""

from __future__ import annotations

import sys
import threading

from sniffdash.plugins import LazyDiscovery


def test_concurrent_first_use_sees_complete_registry(tmp_path, monkeypatch):
    pkg = tmp_path / "slowplugins"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("LOADED = []\n")
    (pkg / "slow.py").write_text(
        "import time\nimport slowplugins\ntime.sleep(0.2)\nslowplugins.LOADED.append('slow')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "slowplugins", raising=False)

    discovery = LazyDiscovery("slowplugins")
    seen: list[int] = []
    start = threading.Barrier(8)

    def worker():
        start.wait()                  # release all threads at the same instant
        discovery.ensure()
        import slowplugins
        seen.append(len(slowplugins.LOADED))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    import slowplugins
    assert seen == [1] * 8                # every thread saw the plugin already loaded
    assert slowplugins.LOADED == ["slow"]  # and it was imported exactly once


def test_none_package_is_a_no_op():
    LazyDiscovery(None).ensure()  # isolated registries in tests use package=None

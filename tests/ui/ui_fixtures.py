"""Fixtures for headless dashboard tests (Streamlit AppTest).

Imported explicitly by the UI test modules (``from ui_fixtures import app, demo_dir``).
Deliberately NOT named conftest.py: a second ``conftest`` module would shadow
``tests/conftest.py``, which other test files import helpers from.

Hermetic by construction:
* captures come from a temp folder of demo files (SNIFFDASH_CAPTURE_DIR), never the user's;
* the real .env / API key is never loaded: services are built without an env file;
* both Streamlit caches are cleared before and after every test (audit A8), because
  ``st.cache_resource`` would otherwise leak loaded captures between tests and hide bugs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from sniffdash.demo import write_demo_captures

APP = Path(__file__).resolve().parents[2] / "app.py"


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory) -> Path:
    folder = tmp_path_factory.mktemp("ui_captures")
    write_demo_captures(folder)
    (folder / "broken.pcap").write_bytes(b"this is not a capture" * 10)
    return folder


@pytest.fixture
def app(demo_dir, monkeypatch):
    from sniffdash.application import build_services
    from sniffdash.ui import cache

    monkeypatch.setenv("SNIFFDASH_CAPTURE_DIR", str(demo_dir))
    for key in ("GEMINI_API_KEY", "GEMINI_MODEL"):
        monkeypatch.setenv(key, "placeholder")   # record original state, then remove for this test
        monkeypatch.delenv(key)
    monkeypatch.setattr(cache, "build_services", lambda: build_services(env_file=None))
    cache.clear_all()
    at = AppTest.from_file(str(APP), default_timeout=120)
    yield at
    cache.clear_all()

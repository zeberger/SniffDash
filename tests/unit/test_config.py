"""Unit tests for settings loading (.env + environment precedence)."""

from __future__ import annotations

import pytest

from sniffdash.config import DEFAULT_GEMINI_MODEL, Settings, load_settings

KEYS = ("GEMINI_API_KEY", "GEMINI_MODEL", "TSHARK_PATH")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Hermetic: the developer's real key must not leak into (or break) these tests.
    # setenv first so monkeypatch records the original state; then any value that
    # load_dotenv writes during the test is removed again afterwards.
    for key in KEYS:
        monkeypatch.setenv(key, "placeholder")
        monkeypatch.delenv(key)


def test_values_come_from_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=abc123\nGEMINI_MODEL=gemini-test\nTSHARK_PATH=C:/ws/tshark.exe\n")
    s = load_settings(env)
    assert (s.gemini_api_key, s.gemini_model, s.tshark_path) == ("abc123", "gemini-test", "C:/ws/tshark.exe")


def test_real_environment_wins_over_env_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("GEMINI_MODEL=from-file\n")
    monkeypatch.setenv("GEMINI_MODEL", "from-environment")
    assert load_settings(env).gemini_model == "from-environment"


def test_missing_env_file_is_fine(tmp_path):
    s = load_settings(tmp_path / "does-not-exist.env")
    assert s.gemini_api_key is None and s.gemini_model == DEFAULT_GEMINI_MODEL


def test_repr_never_shows_the_key():
    assert "secret" not in repr(Settings(gemini_api_key="secret")) and "<set>" in repr(Settings(gemini_api_key="x"))

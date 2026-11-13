"""Unit tests for GeminiClient (AC3, AC5, AC10), with a fake SDK transport.

Responses are built from the REAL ``google.genai.types`` classes, so the adapter is
tested against the actual SDK data shapes. Only the network call is replaced.
"""

from __future__ import annotations

import pytest
from google.genai import errors, types

from sniffdash.config import Settings
from sniffdash.domain.errors import LLMAuthError, LLMContextOverflowError, LLMError, LLMRateLimitError
from sniffdash.llm.client import FALLBACK_COOLDOWN_S, RETRY_STATUS_CODES, GeminiClient, ToolCall, ToolResult, Turn

TOOLS = [{"name": "get_frames", "description": "frames",
          "parameters": {"type": "object", "properties": {"frame_numbers": {"type": "array",
                                                                             "items": {"type": "integer"}}}}}]


class FakeModels:
    """``error`` fails every call; ``errors`` fails calls in order (None = succeed)."""

    def __init__(self, response=None, error=None, errors=()):
        self.response, self.error, self.errors, self.calls = response, error, list(errors), []

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        error = self.errors.pop(0) if self.errors else self.error
        if error:
            raise error
        return self.response


class FakeSdk:
    def __init__(self, **kwargs):
        self.models = FakeModels(**kwargs)


def reply_with(*parts, finish=types.FinishReason.STOP):
    return types.GenerateContentResponse(candidates=[types.Candidate(
        content=types.Content(role="model", parts=list(parts)), finish_reason=finish)])


def call_part(name, args, call_id=None):
    return types.Part(function_call=types.FunctionCall(name=name, args=args, id=call_id))


def client(settings=None, clock=None, **kwargs):
    sdk = FakeSdk(**kwargs)
    settings = settings or Settings(gemini_model="gemini-test", gemini_fallback_model=None)
    extra = {"clock": clock} if clock else {}
    return GeminiClient(settings, sdk_client=sdk, **extra), sdk


def test_request_shape():
    c, sdk = client(response=reply_with(call_part("get_frames", {"frame_numbers": [4]})))
    c.complete("SYSTEM", [Turn("user", text="hi")], TOOLS)
    sent = sdk.models.calls[0]
    config = sent["config"]
    assert sent["model"] == "gemini-test"
    assert config.system_instruction == "SYSTEM" and config.temperature == 0.0
    assert config.tool_config.function_calling_config.mode == types.FunctionCallingConfigMode.ANY
    assert config.automatic_function_calling.disable is True
    declaration, = config.tools[0].function_declarations
    assert declaration.name == "get_frames" and declaration.parameters_json_schema == TOOLS[0]["parameters"]
    assert sent["contents"][0].parts[0].text == "hi"


def test_parallel_function_calls_are_parsed():
    c, _ = client(response=reply_with(call_part("get_frames", {"frame_numbers": [4]}, "c1"),
                                      call_part("get_frames", {"frame_numbers": [5]}, "c2")))
    reply = c.complete("S", [Turn("user", text="q")], TOOLS)
    assert reply.tool_calls == (ToolCall("get_frames", {"frame_numbers": [4]}, "c1"),
                                ToolCall("get_frames", {"frame_numbers": [5]}, "c2"))
    assert reply.raw is not None   # kept so it can be echoed back with thought signatures


def test_model_turn_is_echoed_back_unchanged_and_tool_results_become_function_responses():
    original = types.Content(role="model", parts=[call_part("get_frames", {"frame_numbers": [4]}, "c1")])
    c, sdk = client(response=reply_with(call_part("submit_answer", {})))
    c.complete("S", [Turn("user", text="q"),
                     Turn("model", tool_calls=(ToolCall("get_frames", {}, "c1"),), raw=original),
                     Turn("tool", tool_results=(ToolResult("get_frames", {"frames": []}, "c1"),))], TOOLS)
    contents = sdk.models.calls[0]["contents"]
    assert contents[1] is original                                    # not rebuilt
    response = contents[2].parts[0].function_response
    assert (response.name, response.id, response.response) == ("get_frames", "c1", {"frames": []})


def test_safety_block_is_a_clear_error():
    c, _ = client(response=reply_with(types.Part(text=""), finish=types.FinishReason.SAFETY))
    with pytest.raises(LLMError, match="safety filter"):
        c.complete("S", [Turn("user", text="q")], TOOLS)


def test_empty_response_is_an_error():
    c, _ = client(response=types.GenerateContentResponse(candidates=[]))
    with pytest.raises(LLMError, match="no answer"):
        c.complete("S", [Turn("user", text="q")], TOOLS)


def api_error(code, message="boom", status="X"):
    return errors.ClientError(code, {"error": {"code": code, "message": message, "status": status}})


@pytest.mark.parametrize("error, expected, fragment", [
    (api_error(401), LLMAuthError, "API key"),
    (api_error(403), LLMAuthError, "restricted"),
    (api_error(429, status="RESOURCE_EXHAUSTED"), LLMRateLimitError, "quota"),
    (api_error(404), LLMError, "GEMINI_MODEL"),
    (api_error(400, "input token count exceeds the maximum"), LLMContextOverflowError, "too large"),
    (api_error(400, "bad schema"), LLMError, "rejected the request"),
    (errors.ServerError(503, {"error": {"code": 503, "message": "overloaded", "status": "UNAVAILABLE"}}),
     LLMError, "service error"),
    (ConnectionError("no route"), LLMError, "Could not reach"),
])
def test_error_mapping(error, expected, fragment):
    c, _ = client(error=error)
    with pytest.raises(expected, match=fragment):
        c.complete("S", [Turn("user", text="q")], TOOLS)


QUOTA = api_error(429, status="RESOURCE_EXHAUSTED")
SUBMIT = reply_with(call_part("submit_answer", {}))


def test_thinking_level_is_sent_and_can_be_turned_off():
    """Plan R1.3: 'low' thinking took a question from 19.9 s to 5.5 s, measured live."""
    c, sdk = client(Settings(gemini_model="m", gemini_thinking_level="low"), response=SUBMIT)
    c.complete("S", [Turn("user", text="q")], TOOLS)
    assert sdk.models.calls[0]["config"].thinking_config.thinking_level == types.ThinkingLevel.LOW
    c, sdk = client(Settings(gemini_model="m", gemini_thinking_level=None), response=SUBMIT)
    c.complete("S", [Turn("user", text="q")], TOOLS)
    assert sdk.models.calls[0]["config"].thinking_config is None      # the model's own default


def test_quota_switches_to_the_fallback_model_then_returns_after_the_cooldown():
    now = [0.0]
    c, sdk = client(Settings(gemini_model="main", gemini_fallback_model="lite"), clock=lambda: now[0],
                    errors=[QUOTA], response=SUBMIT)
    with pytest.raises(LLMRateLimitError) as caught:
        c.complete("S", [Turn("user", text="q")], TOOLS)
    assert caught.value.switched_model == "lite" and c.active_model == "lite"
    c.complete("S", [Turn("user", text="q")], TOOLS)
    now[0] = FALLBACK_COOLDOWN_S + 1
    c.complete("S", [Turn("user", text="q")], TOOLS)
    assert [call["model"] for call in sdk.models.calls] == ["main", "lite", "main"]


def test_quota_on_the_fallback_too_is_a_plain_quota_error():
    c, _ = client(Settings(gemini_model="main", gemini_fallback_model="lite"), errors=[QUOTA, QUOTA])
    with pytest.raises(LLMRateLimitError):
        c.complete("S", [Turn("user", text="q")], TOOLS)
    with pytest.raises(LLMRateLimitError, match="both the main and the fallback") as caught:
        c.complete("S", [Turn("user", text="q")], TOOLS)
    assert caught.value.switched_model is None


def test_overloaded_main_model_switches_to_the_fallback():
    """Measured 2026-11-13: the main model returned 504s after retries while the lite model answered."""
    overloaded = errors.ServerError(504, {"error": {"code": 504, "message": "Deadline expired",
                                                    "status": "DEADLINE_EXCEEDED"}})
    c, sdk = client(Settings(gemini_model="main", gemini_fallback_model="lite"), errors=[overloaded], response=SUBMIT)
    with pytest.raises(LLMError, match="Switching to 'lite'") as caught:
        c.complete("S", [Turn("user", text="q")], TOOLS)
    assert caught.value.switched_model == "lite"
    c.complete("S", [Turn("user", text="q")], TOOLS)
    assert [call["model"] for call in sdk.models.calls] == ["main", "lite"]


def test_no_fallback_configured_means_no_switch():
    c, _ = client(error=QUOTA)
    with pytest.raises(LLMRateLimitError) as caught:
        c.complete("S", [Turn("user", text="q")], TOOLS)
    assert caught.value.switched_model is None and c.active_model == "gemini-test"


def test_transient_server_errors_are_retried_but_quota_is_not():
    assert 504 in RETRY_STATUS_CODES and 503 in RETRY_STATUS_CODES and 429 not in RETRY_STATUS_CODES


def test_missing_key_explains_how_to_get_one():
    with pytest.raises(LLMAuthError, match="aistudio.google.com"):
        GeminiClient(Settings(gemini_api_key=None))


def test_only_the_adapter_imports_the_sdk():
    # AC10: provider isolation, checked on the source files themselves.
    from pathlib import Path
    import sniffdash
    root = Path(sniffdash.__file__).parent
    importers = sorted(str(p.relative_to(root)) for p in root.rglob("*.py")
                       if "google.genai" in p.read_text(encoding="utf-8") or "from google import genai"
                       in p.read_text(encoding="utf-8"))
    assert importers == [str(Path("llm") / "client.py")]

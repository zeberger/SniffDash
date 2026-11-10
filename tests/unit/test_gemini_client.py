"""Unit tests for GeminiClient (AC3, AC5, AC10), with a fake SDK transport.

Responses are built from the REAL ``google.genai.types`` classes, so the adapter is
tested against the actual SDK data shapes. Only the network call is replaced.
"""

from __future__ import annotations

import pytest
from google.genai import errors, types

from sniffdash.config import Settings
from sniffdash.domain.errors import LLMAuthError, LLMContextOverflowError, LLMError, LLMRateLimitError
from sniffdash.llm.client import GeminiClient, ToolCall, ToolResult, Turn

TOOLS = [{"name": "get_frames", "description": "frames",
          "parameters": {"type": "object", "properties": {"frame_numbers": {"type": "array",
                                                                             "items": {"type": "integer"}}}}}]


class FakeModels:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        if self.error:
            raise self.error
        return self.response


class FakeSdk:
    def __init__(self, **kwargs):
        self.models = FakeModels(**kwargs)


def reply_with(*parts, finish=types.FinishReason.STOP):
    return types.GenerateContentResponse(candidates=[types.Candidate(
        content=types.Content(role="model", parts=list(parts)), finish_reason=finish)])


def call_part(name, args, call_id=None):
    return types.Part(function_call=types.FunctionCall(name=name, args=args, id=call_id))


def client(**kwargs):
    sdk = FakeSdk(**kwargs)
    return GeminiClient(Settings(gemini_model="gemini-test"), sdk_client=sdk), sdk


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

"""LLMClient (Adapter): the only place that knows which AI provider we use.

The rest of the LLM layer speaks a small provider-neutral language: ``Turn``,
``ToolCall``, ``ToolResult``, ``LLMReply``. ``GeminiClient`` translates it to and
from the ``google-genai`` SDK. Switching provider (OpenAI → Gemini already
happened once) means writing one new class here.

Gemini specifics handled here:
* Function calling is forced (mode ANY): every model turn is a function call,
  either a query tool or ``submit_answer``. Automatic function calling is OFF so
  our code runs, and validates, every tool.
* The model's own reply is echoed back *unchanged* (``Turn.raw``): newer Gemini
  models attach "thought signatures" to function calls and reject a conversation
  where they're missing.
* Thinking is set to ``GEMINI_THINKING_LEVEL`` (default "low"): our questions are
  lookups, and full thinking made one question take 20 s instead of 5.5 s.
* SDK-level retries with exponential backoff for transient server errors
  (500/502/503/504). A 429 (quota used up) is NOT retried: waiting rarely helps.
  After a 429, or a server error that outlasts the retries (measured 2026-11-13: the
  main model returned intermittent 504s while the lite model answered), the client
  switches to ``GEMINI_FALLBACK_MODEL`` (separate quota) for ``FALLBACK_COOLDOWN_S``,
  then tries the main model again. SDK errors are mapped to SniffDash's typed
  ``LLMError`` family.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from sniffdash.config import Settings
from sniffdash.domain.errors import LLMAuthError, LLMContextOverflowError, LLMError, LLMRateLimitError


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    call_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    name: str
    content: dict[str, Any]
    call_id: str | None = None


@dataclass(frozen=True, slots=True)
class Turn:
    role: Literal["user", "model", "tool"]
    text: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    raw: Any = field(default=None, compare=False, repr=False)  # provider-native message, echoed back as-is


@dataclass(frozen=True, slots=True)
class LLMReply:
    text: str | None
    tool_calls: tuple[ToolCall, ...]
    raw: Any = field(default=None, compare=False, repr=False)


class LLMClient(ABC):
    @abstractmethod
    def complete(self, system: str, turns: Sequence[Turn], tools: Sequence[dict[str, Any]]) -> LLMReply:
        """One model call. ``tools`` are neutral declarations {name, description, parameters}."""

    @property
    def active_model(self) -> str | None:
        """The model the next call will use (None when the client doesn't say)."""
        return None


AI_STUDIO_KEY_URL = "https://aistudio.google.com/apikey"
RETRY_STATUS_CODES = [500, 502, 503, 504]  # transient server errors; 429 is handled by the fallback model
FALLBACK_COOLDOWN_S = 600.0                # after a 429, stay on the fallback this long, then retry the main model


class GeminiClient(LLMClient):
    def __init__(self, settings: Settings, *, sdk_client: Any = None, timeout_s: float = 60.0,
                 retry_attempts: int = 3, clock: Callable[[], float] = time.monotonic) -> None:
        self._model = settings.gemini_model
        self._fallback = settings.gemini_fallback_model if settings.gemini_fallback_model != self._model else None
        self._thinking_level = settings.gemini_thinking_level
        self._clock = clock
        self._fallback_until = float("-inf")
        if sdk_client is not None:  # tests inject a fake; no network, no key needed
            self._sdk = sdk_client
            return
        if not settings.gemini_api_key:
            raise LLMAuthError(f"GEMINI_API_KEY is not set. Get a free key at {AI_STUDIO_KEY_URL} "
                               "and add GEMINI_API_KEY=... to your .env file.")
        from google import genai
        from google.genai import types
        self._sdk = genai.Client(
            api_key=settings.gemini_api_key,
            http_options=types.HttpOptions(
                timeout=int(timeout_s * 1000),
                retry_options=types.HttpRetryOptions(attempts=retry_attempts,
                                                     http_status_codes=RETRY_STATUS_CODES),
            ),
        )

    @property
    def active_model(self) -> str:
        return self._fallback if self._fallback and self._clock() < self._fallback_until else self._model

    # --- request -------------------------------------------------------------------

    def complete(self, system: str, turns: Sequence[Turn], tools: Sequence[dict[str, Any]]) -> LLMReply:
        from google.genai import errors, types

        model = self.active_model
        config = types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.0,
            tools=[types.Tool(function_declarations=[
                types.FunctionDeclaration(name=t["name"], description=t["description"],
                                          parameters_json_schema=t["parameters"]) for t in tools])],
            tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(
                mode=types.FunctionCallingConfigMode.ANY)),
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            thinking_config=types.ThinkingConfig(thinking_level=self._thinking_level)
            if self._thinking_level else None,
        )
        try:
            response = self._sdk.models.generate_content(
                model=model, contents=[self._content(t) for t in turns], config=config)
        except errors.ClientError as exc:
            raise self._map_client_error(exc, model) from exc
        except errors.APIError as exc:  # ServerError, still failing after the SDK's retries
            switched = self._switch_to_fallback(model)
            raise LLMError(f"Gemini service error ({exc.code}): {exc.message}"
                           + (f" Switching to '{switched}'." if switched else ""),
                           switched_model=switched) from exc
        except LLMError:
            raise
        except Exception as exc:  # network failures, timeouts
            raise LLMError(f"Could not reach Gemini: {exc}") from exc
        return self._reply(response)

    @staticmethod
    def _content(turn: Turn) -> Any:
        from google.genai import types

        if turn.raw is not None:
            return turn.raw  # the model's own message, thought signatures intact
        if turn.role == "tool":
            return types.Content(role="user", parts=[
                types.Part(function_response=types.FunctionResponse(
                    id=r.call_id, name=r.name, response=r.content)) for r in turn.tool_results])
        if turn.role == "model":
            return types.Content(role="model", parts=[
                types.Part(function_call=types.FunctionCall(id=c.call_id, name=c.name, args=c.arguments))
                for c in turn.tool_calls] or [types.Part(text=turn.text or "")])
        return types.Content(role="user", parts=[types.Part(text=turn.text or "")])

    # --- response ------------------------------------------------------------------

    @staticmethod
    def _reply(response: Any) -> LLMReply:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            feedback = getattr(response, "prompt_feedback", None)
            reason = getattr(feedback, "block_reason", None)
            raise LLMError(f"Gemini returned no answer{f' (blocked: {reason})' if reason else ''}.")
        candidate = candidates[0]
        finish = str(getattr(candidate, "finish_reason", "") or "")
        if "SAFETY" in finish or "PROHIBITED" in finish:
            raise LLMError("Gemini's safety filter blocked this response. Try rephrasing the question.")
        parts = getattr(candidate.content, "parts", None) or []
        calls = tuple(ToolCall(name=p.function_call.name, arguments=dict(p.function_call.args or {}),
                               call_id=getattr(p.function_call, "id", None))
                      for p in parts if getattr(p, "function_call", None))
        text = "".join(p.text for p in parts if getattr(p, "text", None)) or None
        return LLMReply(text=text, tool_calls=calls, raw=candidate.content)

    def _switch_to_fallback(self, failed_model: str) -> str | None:
        """Use the fallback for the cooldown period; returns its name, or None if there's nowhere to go."""
        if not self._fallback or failed_model == self._fallback:
            return None
        self._fallback_until = self._clock() + FALLBACK_COOLDOWN_S
        return self._fallback

    def _map_client_error(self, exc: Any, model: str) -> LLMError:
        message = str(getattr(exc, "message", "") or exc)
        code = getattr(exc, "code", None)
        if code in (401, 403):
            return LLMAuthError(f"Gemini rejected the API key ({code}). Check GEMINI_API_KEY in .env, and that "
                                f"the key is restricted to the Gemini API in AI Studio.")
        if code == 429:
            if switched := self._switch_to_fallback(model):
                return LLMRateLimitError(f"The quota of '{model}' is used up; switching to '{switched}'.",
                                         switched_model=switched)
            return LLMRateLimitError("Gemini quota reached (free tier limits requests per minute and per day"
                                     + (", on both the main and the fallback model" if self._fallback else "")
                                     + "). Wait a minute and retry, or try again tomorrow.")
        if code == 404:
            setting = "GEMINI_FALLBACK_MODEL" if model == self._fallback else "GEMINI_MODEL"
            return LLMError(f"Model '{model}' is not available to this key. Set {setting} in .env "
                            f"to a model listed in AI Studio.")
        if code == 400 and "token" in message.lower():
            return LLMContextOverflowError(f"The request was too large for the model: {message}")
        return LLMError(f"Gemini rejected the request ({code}): {message}")

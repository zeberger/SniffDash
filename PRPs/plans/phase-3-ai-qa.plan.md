# Answer questions about a capture with verified evidence, adapted to the user's skill level

**Plan ID:** `phase-3-ai-qa`
**Source PRD:** `PRPs/prds/sniffdash.prd.md`
**PRD Phase:** `3 — AI Q&A`
**Source Issue:** `None`

## Outcome

**Problem:** Module 3 requires plain-language questions about a capture, answered with cited frame numbers and
timestamps (Reqs 30–34). A language model left alone guesses numbers and invents frame numbers. The user also wants
answers pitched at the asker's level, and insight into **encrypted (HTTPS) traffic**, where the payload can't be read
but its shape can.

**Affected user:** The student or grader asking questions through Phase 4's chat box, from beginner to expert.

**User outcome:** `LLMService.ask(question, report, repo, skill_level=…)` returns an answer in the requested style plus
evidence items (frame number, timestamp, claim). Every cited frame is **checked against the capture**. Encrypted flows
are summarized by observable metadata (sizes, timing, bursts) with an explainable traffic-type inference.

**Invariant:** No frame number or timestamp reaches the user as evidence unless it exists in the capture and matches it.
Exact quantities come from deterministic code, never from the model's arithmetic. The skill level changes the
*explanation style only*, never the facts or the evidence rules.

**Success signal:** On the reference capture, a live Gemini run of the four required question types returns the known
answers (slowest = `tx-4`, 120 ms, frames 4→5; 2 requests to `example.com`; statuses 200 and 404 plus one unanswered;
an explanation of `tx-4`) with 100% valid citations, at all three skill levels. On the synthetic HTTPS captures, the
three traffic patterns are classified correctly.

**Approach:**
- A token-budgeted JSON **context**.
- Deterministic **query tools** that the model calls through Gemini function calling.
- The final answer is delivered through a dedicated **`submit_answer` function call**, so it is structured on every Gemini model.
- A versioned **system prompt** composed with a **skill-level section**.
- A **`GeminiClient`** adapter (`google-genai`).
- A **citation validator**.
- A new **`EncryptedFlowAnalyzer`** plugin with matching tools.

## Recommendation

1. **Tools compute, the model explains.** Each required query maps to a deterministic tool over Phase 2's `HttpAnalysisResult`.
2. **The final answer is a function call, not a response schema.** Google's docs state that function calling *combined
   with* structured output (`response_schema`) is supported only on Gemini 3-series models, as a preview. Instead we
   declare `submit_answer(answer, evidence[], insufficient_data)` as one more function and set function calling to mode
   `ANY`, so every model turn must call a function: either a query tool or `submit_answer`. This works on every
   function-calling model (2.5 and 3.x), gives a structured answer on every turn, and removes the free-text JSON parsing
   step entirely.
3. **The encrypted-traffic analysis is a new analyzer plugin**, which exercises the Phase 2 registry (Open/Closed) instead of
   special-casing HTTPS inside the LLM layer. Its features are deterministic. Its traffic-type label is an explicit,
   rule-based inference, with the reasons listed, never presented as fact.

### Evidence

- `google-genai` 3.0.0 (installed and inspected):
  - `GenerateContentConfig` has `system_instruction`, `tools`, `tool_config`, `response_schema`, `temperature`,
    `automatic_function_calling`, `thinking_config`, `http_options`, `seed`;
  - `FunctionDeclaration.parameters_json_schema` takes plain JSON Schema;
  - `FunctionCallingConfigMode` includes `ANY` and `VALIDATED`, with `allowed_function_names`;
  - `HttpRetryOptions(attempts, initial_delay, max_delay, exp_base, jitter, http_status_codes)` provides built-in backoff;
  - errors are `APIError` → `ClientError` (4xx) / `ServerError` (5xx), with `code`, `status`, `message`.
- Google docs: function calling plus structured output is limited to Gemini 3-series (preview); Gemini 2.5 Flash / Pro /
  Flash-Lite and 3.x support function calling. Free-tier quotas are per model, shown in AI Studio, best-effort, and can be
  very small (community reports as low as 20 requests/day on some models). Since June 2026 the API rejects unrestricted
  API keys.
- `src/sniffdash/domain/results.py:101-121` — `HttpAnalysisResult` holds every required answer.
- `src/sniffdash/analysis/analyzers/http/stream.py:23-40` — `HttpStreamReconstructor` serves "explain this stream".
- `src/sniffdash/analysis/base.py:52-80` — the analyzer registry the encrypted-flow plugin joins, and the pattern the tool registry mirrors.
- `src/sniffdash/parsing/extractors/tls.py` — PyShark already extracts `tls.sni`; Scapy has no TLS dissector, so flows
  are detected by TLS layer **or** server port 443/8443, which keeps both backends equal.
- `src/sniffdash/domain/errors.py:64-82` — the `LLMError` hierarchy declared in Phase 1.

### Alternatives considered

- **`response_schema` together with tools:** only Gemini 3 preview models support it, so it would tie the project to a preview model.
- **Two calls per question (tools, then a schema-only call):** an extra request each time, which matters under free-tier quotas.
- **ML-based traffic classification:** needs labeled training data and isn't explainable. Rule-based features are transparent and testable.
- **`tiktoken` / Gemini `count_tokens`:** a native dependency, or a network call per question, for a number used only as a
  ceiling. A conservative local estimate (1 token ≈ 3 characters of JSON) is enough.

## Visuals

```
question, skill_level ──► LLMService.ask
   system_instruction = system_v1.md + levels/<level>.md
   contents = [capture context (ContextBuilder JSON), question]
        ▼
   ┌─ GeminiClient.complete(contents, tools + submit_answer, mode=ANY, temperature=0) ◄──┐
   │    (google-genai; HttpRetryOptions backoff; typed error mapping)                    │
   │  function_calls:                                                                     │
   │    query tools ──► ToolRegistry.run ──► function_response parts ────────────────────┘ (≤ 4 rounds)
   │      slowest_http_requests · count_requests_by_host · status_code_summary ·
   │      get_transaction · get_frames · encrypted_flows · get_encrypted_flow
   └─ submit_answer(args) ──► schema check (1 repair turn) ──► CitationValidator ──► ValidatedAnswer

FrameRepository ──► EncryptedFlowAnalyzer (registry plugin) ──► EncryptedFlowsResult
   per TCP stream with TLS or port 443/8443: up/down packets & bytes, size stats, inter-arrival times (IAT),
   bursts, periodicity ──► rule-based label + reasons + first/last frame evidence
```

## Implementation Context

### Mandatory reading

| File | Why it matters |
|---|---|
| `src/sniffdash/domain/results.py:43-150` | Result types the context, tools and the new analyzer use |
| `src/sniffdash/analysis/base.py:24-80` | Analyzer contract and registry: the new plugin and the tool registry follow it |
| `src/sniffdash/analysis/analyzers/http/stream.py:23-40` | Reused by `get_transaction` |
| `src/sniffdash/parsing/extractors/tls.py` | The TLS fields available (SNI) |
| `tests/conftest.py` | Reference scenario, `analyze_file`, capture builders to extend |

### Existing patterns and primitives

- **Analyzer plugin:** `TimelineAnalyzer` (`src/sniffdash/analysis/analyzers/timeline.py`) is the closest precedent for a vectorized, registry-discovered analyzer.
- **Dependency Injection:** `AnalysisEngine(analyzers=…)` → `LLMService(client=…)`, so tests script the model and never use the network.

### Integration points

- Phase 4's chat calls `LLMService.ask` with the user's chosen skill level, renders `ValidatedAnswer`, and loads settings through `sniffdash.config`.

## Scope

### In scope

- `GeminiClient` adapter; `.env` loading of `GEMINI_API_KEY` / `GEMINI_MODEL` (moved forward from Phase 4)
- Token-budgeted context (Req 30); `LLMService.ask` entry point (Req 31)
- Tools for the required query types (Req 32) and for encrypted flows
- `submit_answer` structured answers with evidence; citation validation (Reqs 33–34)
- Skill levels: `beginner` / `intermediate` / `expert`
- `EncryptedFlowAnalyzer`: metadata features and explainable traffic-type inference
- Credential redaction before anything is sent to Google
- Tests with a scripted client; opt-in live Gemini smoke test

### Not building

- Chat UI and skill-level selector — Phase 4
- Decrypting TLS — out of scope; metadata only
- ML traffic classification — rule-based only (explainable, testable)
- Streaming output and multi-turn memory — each question is answered from the capture alone, which keeps citations verifiable

## Delivery Considerations

| Concern | Decision and owned work |
|---|---|
| Privacy | Google's free-tier terms allow prompts to be used to improve Google products. Tools redact `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie`, and truncate bodies to 2,000 characters. The README and Phase 4 UI say what is sent. |
| Quota | The free tier is small, and each question costs 1–5 requests. Mitigations: the context pre-answers common questions; mode `ANY` plus parallel function calls; at most 4 tool rounds; a 429 becomes a clear "quota reached, retry later" message. |
| Model availability | `GEMINI_MODEL` is configurable (default `gemini-2.5-flash`). A 404 from the API produces a message telling the user to set `GEMINI_MODEL` to a model listed in AI Studio. |
| Compatibility | `.env.example` replaces `OPENAI_*` with `GEMINI_API_KEY` / `GEMINI_MODEL`. The `openai` package is dropped from the dependencies. |
| Documentation | README: getting a free AI Studio key, restricting it to the Gemini API, `.env` setup, skill levels, what data is sent. |

## Implementation

### 1. Settings and `.env` loading

**Files and integration points**
- `src/sniffdash/config.py` — CREATE — `Settings(gemini_api_key, gemini_model, tshark_path)`, `load_settings(env_file=".env")`

**Implementation**
- `python-dotenv` (already a dependency) loads `.env` without overriding real environment variables. This is called explicitly, never at import time, so tests stay hermetic.
- This also resolves Phase 1's R1: `TSHARK_PATH` in `.env` now works once `load_settings()` has run.

**Tests**
- `tests/unit/test_config.py`: values come from a temp `.env`; real env vars win; a missing file is fine; the default model applies.

**Validation**
- `python -m pytest -q tests/unit/test_config.py` — all pass.

### 2. Encrypted-flow metadata analyzer (creativity feature)

**Files and integration points**
- `src/sniffdash/analysis/analyzers/encrypted.py` — CREATE — `EncryptedFlowAnalyzer` (`@register_analyzer`)
- `src/sniffdash/domain/results.py` — UPDATE — `EncryptedFlow`, `EncryptedFlowsResult` (key `"encrypted_flows"`)

**Implementation**
- **Flows:** TCP streams containing a TLS layer, or with server port 443/8443. The client is the SYN sender, or the non-443 side.
- **Features per flow:**
  - packets and payload bytes up/down;
  - duration;
  - downstream packet-size mean/median/max;
  - inter-arrival time (IAT) mean/median/p95 and coefficient of variation;
  - bursts (split at idle > 0.5 s): count, mean bytes, interval regularity;
  - down/up byte ratio;
  - SNI when known;
  - first/last frame numbers and timestamps (citable).
- **Rule-based label**, with the thresholds in one documented table and each label giving the reasons that fired:
  - `video_streaming` — duration ≥ 10 s, ≥ 1 MB down, ≥ 3 regular bursts, down/up ≥ 10;
  - `file_or_image_download` — one burst carrying ≥ 80% of ≥ 50 KB down, short;
  - `api_polling` — ≥ 4 small bursts (< 10 KB) at regular intervals;
  - `interactive_or_mixed` — otherwise.
- The label is always phrased as an inference.

**Tests**
- `tests/unit/test_encrypted_flows.py` with hand-made frames: feature arithmetic, burst splitting, each rule, non-HTTPS traffic ignored.
- `tests/integration/test_encrypted_reference.py`: three synthetic HTTPS captures (TLS application-data records on port 443) — streaming, download and polling — are each classified correctly on both backends.

**Validation**
- `python -m pytest -q tests/unit/test_encrypted_flows.py tests/integration/test_encrypted_reference.py` — all pass.

### 3. Answer models and citation validation

**Files and integration points**
- `src/sniffdash/llm/answer.py` — CREATE — `Evidence`, `GroundedAnswer`, `CitationIssue`, `ValidatedAnswer`, `SkillLevel` (StrEnum), `ANSWER_SCHEMA`
- `src/sniffdash/llm/citations.py` — CREATE — `CitationValidator(repo).validate(answer)`

**Implementation**
- ISO-8601 UTC timestamps with milliseconds everywhere. A citation is valid when the frame exists and the timestamp is within 1 ms. Frame numbers mentioned in the answer text are checked too.

**Tests**
- `tests/unit/test_citations.py`: a valid citation; a missing frame; a wrong or unparseable timestamp; an unverified frame in the text; `insufficient_data` with no evidence.

**Validation**
- `python -m pytest -q tests/unit/test_citations.py` — all pass.

### 4. Token-budgeted context (Req 30)

**Files and integration points**
- `src/sniffdash/llm/context.py` — CREATE — `ContextBuilder(budget_tokens=6000).build(report)`, `estimate_tokens(text)`

**Implementation**
- Sections in priority order:
  1. capture;
  2. protocols;
  3. top talkers;
  4. http_overview, including the 5 slowest;
  5. encrypted_overview (flow count by label);
  6. transaction_index, truncated last with `"truncated": {"omitted": N, "hint": "use tools"}`.
- Deterministic. No headers or bodies.

**Tests**
- `tests/unit/test_context.py`: all sections present; a tiny budget truncates only the index; deterministic; an empty capture works.

**Validation**
- `python -m pytest -q tests/unit/test_context.py` — all pass.

### 5. Deterministic query tools (Req 32)

**Files and integration points**
- `src/sniffdash/llm/tools/base.py` — CREATE — `QueryTool`, `ToolContext`, `ToolRegistry` + `@register_tool` (via `LazyDiscovery`)
- `src/sniffdash/llm/tools/http_tools.py` — CREATE — `slowest_http_requests`, `count_requests_by_host`, `status_code_summary`, `get_transaction`
- `src/sniffdash/llm/tools/frame_tools.py` — CREATE — `get_frames` (≤ 50)
- `src/sniffdash/llm/tools/encrypted_tools.py` — CREATE — `encrypted_flows(limit)`, `get_encrypted_flow(stream_id)`
- `src/sniffdash/llm/redaction.py` — CREATE

**Implementation**
- Parameter schemas use the JSON Schema subset Gemini accepts: `type`/`properties`/`required`/`enum`/`items`, no `additionalProperties`, optional values through `required` instead of null unions.
- Every row carries citable frame numbers and ISO timestamps.
- Bad arguments or missing data → `{"error": …}`, returned to the model rather than raised.

**Tests**
- `tests/unit/test_tools.py` (reference + synthetic HTTPS reports):
  - slowest = `tx-4`;
  - `example.com` = 2;
  - statuses {200: 1, 404: 1, unanswered: 1};
  - `tx-13` shows "no response";
  - `Cookie` is redacted;
  - flow tools return label + reasons + frames;
  - every declaration converts to a valid `types.FunctionDeclaration`.

**Validation**
- `python -m pytest -q tests/unit/test_tools.py` — all pass.

### 6. Gemini adapter behind `LLMClient`

**Files and integration points**
- `src/sniffdash/llm/client.py` — CREATE — neutral `ChatTurn` / `ToolCall` / `ToolResult` / `LLMReply`, `LLMClient` ABC, `GeminiClient(settings)`

**Implementation**
- Maps neutral turns to `types.Content` parts (`text`, `function_call`, `function_response`) and the system text to `system_instruction`.
- Request settings:
  - `tool_config` mode `ANY`;
  - automatic function calling **disabled**, so our code runs and validates every tool;
  - `temperature=0`;
  - `HttpRetryOptions(attempts=3, http_status_codes=[429, 500, 503])`.
- Error mapping:
  - 401/403 → `LLMAuthError`;
  - 429 → `LLMRateLimitError`, with a quota hint;
  - 400 naming tokens or context → `LLMContextOverflowError`;
  - 404 → `LLMError` naming `GEMINI_MODEL`;
  - `ServerError` / timeouts → `LLMError`;
  - no candidates or `finish_reason` SAFETY → `LLMError("response blocked by safety filter")`.
- Only this file imports `google.genai`.

**Tests**
- `tests/unit/test_gemini_client.py` uses a fake SDK `models` object returning real `types.GenerateContentResponse` objects (no network): the request shape (system instruction, tools including `submit_answer`, mode `ANY`, AFC off, temperature 0); parallel function calls are parsed; every error maps correctly; the safety block; the missing key.

**Validation**
- `python -m pytest -q tests/unit/test_gemini_client.py` — all pass.

### 7. Skill-aware prompt and the question-answering loop (Reqs 31, 33–34)

**Files and integration points**
- `src/sniffdash/llm/prompts/system_v1.md` — CREATE — grounding and evidence rules, identical for every level
- `src/sniffdash/llm/prompts/levels/{beginner,intermediate,expert}.md` — CREATE — explanation style only
- `src/sniffdash/llm/service.py` — CREATE — `LLMService(client, context_builder=None, tools=None, max_tool_rounds=4).ask(question, report, repo, *, skill_level="intermediate")`
- `pyproject.toml` — UPDATE — `google-genai>=1.30`; remove nothing else; include `prompts/**/*.md` as package data

**Implementation**
- The levels:
  - **Beginner:** concepts in plain words, an analogy where useful, every acronym explained, no jargon without definition.
  - **Intermediate:** standard networking terms with brief clarification.
  - **Expert:** precise protocol-level language (TCP flags, RFC behavior, header semantics), no basics.
- The loop runs query tools (in parallel per turn) until `submit_answer` arrives. A `submit_answer` failing the schema check gets one repair turn, then `LLMResponseFormatError`. Exceeding the round limit → `LLMError`.
- An invalid skill level or an empty question → `ValueError`.

**Tests**
- `tests/unit/test_service.py` with a scripted client:
  - tool → `submit_answer` flow;
  - parallel tool calls;
  - repair succeeds or fails;
  - round limit;
  - invalid citations flagged;
  - each level's style section is present **and** the evidence rules are identical across all three levels.

**Validation**
- `python -m pytest -q tests/unit/test_service.py` — all pass.

### 8. End-to-end and live checks

**Files and integration points**
- `tests/integration/test_llm_reference.py` — CREATE

**Implementation**
- **Scripted:** the four required queries plus one encrypted-flow question on real parsed captures (both backends), with assertions on tool output and validated evidence.
- **Live** (marker `live_llm`, skipped without `GEMINI_API_KEY`): the four questions at the `beginner` and `expert` levels. It asserts the key facts and 100% valid citations, and keeps the request count small for the free tier.

**Validation**
- `python -m pytest -q tests/integration/test_llm_reference.py`; live: `python -m pytest -q -m live_llm`.

## Acceptance

1. **AC1 — Bounded context:** the context stays within budget and truncates only the transaction index, with a note.
2. **AC2 — Exact answers from tools:** slowest = `tx-4` (120 ms, frames 4→5); `example.com` = 2; statuses {200: 1, 404: 1, unanswered: 1}; the full `tx-4` stream.
3. **AC3 — Structured answers on any model:** every final answer arrives through `submit_answer` as `answer` + `evidence[]` + `insufficient_data`, without `response_schema`.
4. **AC4 — Citation verification:** non-existent frames, mismatched timestamps and unverified frame numbers in the text are flagged.
5. **AC5 — Typed failures:** missing key, auth, quota (429), context overflow, unknown model, safety block, malformed `submit_answer` (after repair) and the round limit each map to the right `LLMError`.
6. **AC6 — Privacy:** redacted credentials never appear in any request content.
7. **AC7 — Skill levels:** each level adds its style section; the grounding and evidence rules are byte-identical across levels; an invalid level is rejected.
8. **AC8 — Encrypted flows:** the three synthetic HTTPS patterns are labeled `video_streaming`, `file_or_image_download` and `api_polling` on both backends, each with reasons and citable first/last frames.
9. **AC9 — `.env` configuration:** `GEMINI_API_KEY`, `GEMINI_MODEL` and `TSHARK_PATH` load from `.env`; real environment variables take precedence.
10. **AC10 — Isolation and preservation:** only `llm/client.py` imports `google.genai`; the full suite passes with and without tshark, offline.

## Validation

| Gate | Command or procedure | Proves |
|---|---|---|
| Focused behavior | `python -m pytest -q tests/unit/test_config.py tests/unit/test_encrypted_flows.py tests/unit/test_citations.py tests/unit/test_context.py tests/unit/test_tools.py tests/unit/test_gemini_client.py tests/unit/test_service.py tests/integration/test_encrypted_reference.py tests/integration/test_llm_reference.py` | AC1–AC9 |
| Project gate | `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | AC10, no leaks |
| Portability | `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | AC10 |
| Live grounding | `GEMINI_API_KEY` in `.env`, then `python -m pytest -q -m live_llm` | Success signal (needs your free AI Studio key) |

## Risks and Decisions

| Decision or risk | Recommendation | Evidence / mitigation | Consequence if different |
|---|---|---|---|
| Final answer via `submit_answer` + mode `ANY` | Adopt | Tools + `response_schema` only on Gemini 3 preview | Using `response_schema` would lock the project to a preview model |
| Default model | `gemini-2.5-flash`, overridable by `GEMINI_MODEL` | Listed for function calling; names change often | If retired, set `GEMINI_MODEL`; the 404 message says so |
| Free-tier quota exhaustion | Budget requests; clear 429 message | Community reports of very low daily limits | Live tests are opt-in and kept minimal |
| Gemini schema subset | Write tool schemas in the subset; unit-test conversion | No `additionalProperties`; optional values via `required` | Unsupported keywords return 400 at runtime |
| Thinking tokens (2.5 models) | Leave the model default | Adds latency and cost but improves tool choice | `thinking_config` can be tuned later in one place |
| Traffic-type inference can be wrong | Label as inference, list the reasons, cite frames | Rules and thresholds in one table, tested on synthetic patterns | Presenting a label as fact would mislead the user |

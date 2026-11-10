# Implementation Report

**Plan:** `PRPs/plans/phase-3-ai-qa.plan.md`
**Branch:** `feat/phase-3-ai-qa`
**Status:** `COMPLETE`

## Outcome

`LLMService.ask(question, report, repo, skill_level=…)` answers natural-language questions about a capture through
Google Gemini.
- **Exact facts:** they come from deterministic tools (slowest request, requests per host, status codes, transaction
  detail, frames, encrypted flows), never from the model's arithmetic.
- **Structured answers:** the answer always arrives through a `submit_answer` function call, so it is structured on
  every Gemini model.
- **Verified evidence:** every cited frame number and timestamp is checked against the capture; mismatches are
  flagged, never hidden.
- **Skill levels:** beginner, intermediate and expert change the explanation style while the evidence rules stay
  byte-identical.
- **HTTPS metadata analysis:** a new `EncryptedFlowAnalyzer` plugin infers the traffic type of encrypted connections
  (video streaming, file/image download, API polling) from sizes and timing, with explicit reasons and citable frames.
- **Privacy:** credentials are redacted before anything is sent to Google.
- **Configuration:** settings load from `.env`.

## Validation

| Command or check | Result | Evidence |
| --- | --- | --- |
| `python -m pytest -q tests/unit/test_config.py tests/unit/test_encrypted_flows.py tests/unit/test_citations.py tests/unit/test_context.py tests/unit/test_tools.py tests/unit/test_gemini_client.py tests/unit/test_service.py tests/integration/test_encrypted_reference.py tests/integration/test_llm_reference.py` | `passed` | 109 passed, 5 live tests skipped (opt-in) |
| `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | `passed` | 323 passed (214 from Phases 1–2 + 109 new), 5 skipped (live) |
| `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | `passed` | 280 passed, 48 skipped |
| `pip install -e ".[dev]"` (prompts shipped as package data) | `passed` | Prompts load through `importlib.resources` |
| Live key checks (`.env` git-ignored and ACL-restricted to the user; key loads; `models.list` accepted) | `passed` | 24 models available, including gemini-2.5 and 3.x |
| Live question, beginner level: "Which HTTP request was the slowest?" on the reference capture | `passed` | `gemini-3.5-flash`: answered `GET /index.html`, 120 ms, frames 4→5; 2/2 citations valid; fully grounded |
| `python -m pytest -q -m live_llm` (full live set, 5 questions) | `passed` | 5 passed (`gemini-3.5-flash`, 49.6 s): slowest = tx-4 / 120 ms; example.com = 2; statuses 200 + 404 + 1 unanswered; tx-4 explained; beginner variant. 15/15 citations valid, 0 invalid |
| Acceptance AC1–AC10 | `passed` | Each AC maps to the tests named in its plan task |

## Deviations and Decisions

- **Live test set reduced to 5 questions** (four required at `expert`, one at `beginner`) instead of four × two levels, because of free-tier daily quotas.
  Live tests run only when explicitly selected with `-m live_llm`, even when a key is present.
- **Gemini "thought signatures":** newer models require their own function-call messages to be sent back unchanged.
  The adapter keeps the raw model message (`Turn.raw`) and echoes it back instead of rebuilding it.
- **Body redaction goes beyond the plan:** besides the four headers, password/secret/token/api_key fields in form or
  JSON bodies are masked.
- **`openai` is no longer a dependency.** The package remains installed in the local `.venv` but is unused, not
  declared, and not imported.
- **Phase 1 extractor fix** (R1 below): Scapy's TCP payload length now excludes Ethernet padding.
- **Default model changed after the live check:** the planned `gemini-2.5-flash` returned 404 ("no longer available
  to new users"), which is exactly the risk listed in the plan, and the 404 → "set GEMINI_MODEL" message worked.
  `gemini-3.8-flash` (Google's suggestion) returned 503 (high demand), while `gemini-3.5-flash` answered correctly, so
  it is the new default.

## Review Dispositions

| ID | Disposition | Reason and evidence | Tracking |
| --- | --- | --- | --- |
| `R1` | `FIXED` | Scapy counted Ethernet padding as TCP payload, so a padded bare ACK looked like 6 data bytes. The byte-volume features of the encrypted-flow analysis depend on this. It is now computed from the IP header like Wireshark's `tcp.len` (`test_scapy_payload_length_ignores_ethernet_padding`). | `Not applicable` |
| `R2` | `FIXED` | When the context was truncated over several rounds, it reported only the last round's dropped rows ("1 omitted" when 3 were missing), which would mislead the model. Now counted against the original total (`test_tiny_budget_truncates_only_the_index`). | `Not applicable` |

## Completion Gate

- **Plan tasks complete:** `Yes`
- **Acceptance criteria satisfied:** `Yes`
- **Unresolved blocker:** `None`
- **Recovery:** `None`

## Intended Commit Scope

The `sniffdash.llm` package (Gemini adapter, context builder, query tools, redaction, answer models, citation
validator, skill-aware prompts, service), `sniffdash.config`, the `EncryptedFlowAnalyzer` plugin and its result
types, the Scapy payload-length fix, the HTTPS capture fixture and 109 new tests, the dependency and package-data
changes, `.env.example`, README, the Phase 3 plan and this report, and the PRD update.

## Delivery

- **Commits:** `5b7a726 docs(prp): record delivery links for PRs #2 and #3`; Phase 3: `Not created`
- **Pull Request:** `Not opened`
- **Base / Head:** `main <- feat/phase-3-ai-qa`
- **Source PRD:** `PRPs/prds/sniffdash.prd.md` — phase 3 marked `complete`
- **Tracked follow-ups:** `None`

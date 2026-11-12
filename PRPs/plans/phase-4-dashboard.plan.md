# Make SniffDash usable in the browser: upload, explore, inspect streams, ask questions

**Plan ID:** `phase-4-dashboard`
**Source PRD:** `PRPs/prds/sniffdash.prd.md`
**PRD Phase:** `4 — Dashboard UI`
**Source Issue:** `None`

## Outcome

**Problem:** Phases 1–3 deliver parsing, analysis and grounded Q&A as Python APIs only. A student or grader can't use
them without writing code, and Reqs 23, 26, 29 and 31 explicitly require an interactive interface: file upload,
charts, a clickable transaction table with stream inspection, and a question box.

**Affected user:** The student or grader analyzing a capture, and anyone who clones the repo (including setup).

**User outcome:** `streamlit run app.py` opens a dashboard where you:
- **upload or pick** a capture;
- see **overview** metrics and interactive charts;
- browse the **HTTP transactions** table and click one to see its "Follow HTTP Stream" view;
- see **encrypted-flow** inferences;
- **ask questions** at a chosen skill level, with verified evidence that links back to frames.

**Invariant:** The UI only *presents*. Every number on screen comes from the Phase 1–3 objects (`AnalysisReport`,
`FrameRepository`, `ValidatedAnswer`) through one facade. No module outside `sniffdash.ui` imports Streamlit, and a
capture is parsed **once** per file, not on every click.

**Success signal:** The manual walkthrough of the PRD User Flow on the demo capture works end-to-end (upload → overview
→ HTTP table → stream → question with evidence), and switching tabs or asking questions never re-parses the capture.

**Approach:**
- An `AnalysisSession` **facade** (application layer, Streamlit-free) loads a capture and exposes ready-to-render tables and actions.
- A thin Streamlit layer: a sidebar, plus tabs built from a **view registry** (Open/Closed). New analyzers get tabs without touching the layout.
- **Caching:** `st.cache_resource` holds the parsed and analyzed capture; `st.cache_data` holds the derived DataFrames.
- **UI tests** with Streamlit's headless `AppTest`.

## Recommendation

Put all UI-facing logic (loading, DataFrame shaping, stream lookup, asking) in a plain-Python `AnalysisSession` facade, and
keep Streamlit code to layout and widgets. The facade is unit-testable without a browser. `AppTest` then covers only the
wiring.

**Caching, decided per kind of object:**
- **Parsed and analyzed capture → `st.cache_resource`:** shared, not copied. This is safe because every Phase 1–3 object is
  immutable, and it avoids re-pickling a large repository on every rerun.
- **Derived DataFrames → `st.cache_data`**, as the user requested in Phase 2: small, and returned as a fresh copy, so a
  widget can't corrupt the cached version.

### Evidence

- Streamlit 1.67.0 (installed and probed): `st.dataframe(on_select=…, selection_mode=…)` for clickable rows;
  `st.cache_data` / `st.cache_resource`; `st.chat_input` / `st.chat_message`; `st.segmented_control`.
- `streamlit.testing.v1.AppTest` drives `selectbox`, `chat_input` and `file_uploader` headlessly, with no exceptions.
- Plotly 7.1.0 for interactive charts.
- `src/sniffdash/domain/results.py` — `CaptureSummary`, `TrafficTimeline`, `HttpAnalysisResult`, `EncryptedFlowsResult`: everything the views render.
- `src/sniffdash/analysis/analyzers/http/stream.py:23` — `HttpStreamReconstructor` for the stream inspector.
- `src/sniffdash/llm/service.py` — `LLMService.ask(...) -> ValidatedAnswer`; `src/sniffdash/config.py` — `load_settings()`.
- `src/sniffdash/parsing/factory.py` — `ParserFactory.default().create(path, backend)`.
- `tests/conftest.py` — `build_http_scenario`, `build_https_flows`: the reference captures, reused as the demo data.

### Alternatives considered

- **Everything in one Streamlit script:** fastest to write, but untestable without a browser and breaks the layering rule.
- **`st.cache_data` for the whole capture:** pickles and copies the repository on every rerun, which is slow for large captures.
  Immutability makes the shared `cache_resource` safe.
- **FastAPI backend + separate frontend:** deferred in the PRD; the facade keeps that path open.

## Visuals

```
app.py (streamlit run app.py) ──► sniffdash.ui.app.main()
  Sidebar: upload .pcap/.pcapng │ or pick from captures/ │ parser: auto/pyshark/scapy │ max packets
        │ bytes + name
        ▼
  ui/cache.py  @st.cache_resource load_capture_cached(bytes, name, backend, max_packets)
        │                                   └► application.load_capture → parse → repo → AnalysisEngine
        ▼
  AnalysisSession (facade, no Streamlit) ──► DataFrames (@st.cache_data in ui) · stream(tx) · ask(q, level)
        ▼
  Tabs from ViewRegistry:  Overview │ HTTP │ Encrypted │ Ask AI │ Issues
     KPI tiles + Plotly     table + row-select → stream inspector     chat + evidence → frame links
```

## Implementation Context

### Mandatory reading

| File | Why it matters |
|---|---|
| `src/sniffdash/domain/results.py` | Every result type the views render |
| `src/sniffdash/llm/answer.py` | `ValidatedAnswer`, `SkillLevel`: what the chat shows |
| `src/sniffdash/llm/client.py` | `LLMError` family → friendly chat messages |
| `src/sniffdash/analysis/base.py:52-80` | Registry pattern for `ViewRegistry` |
| `tests/conftest.py` | Capture builders to move into the package as demo data |

### Existing patterns and primitives

- **Registry + Open/Closed:** `AnalyzerRegistry` → `ViewRegistry`. Each view declares its tab title, order, and whether it applies to a report.
- **Dependency Injection:** `LLMService(client=…)`. The UI gets its service from the facade, and tests inject a `ScriptedClient` through `st.session_state`.

### Integration points

- `load_settings()` (Phase 3) is called once at app start, so `.env` provides `GEMINI_API_KEY` / `GEMINI_MODEL` / `TSHARK_PATH`.

## Scope

### In scope

- `AnalysisSession` facade and `load_capture`; bootstrap wiring of settings, parser factory, engine and LLM service
- Streamlit app:
  - sidebar input: upload, folder picker, parser choice, packet limit;
  - Overview: KPI tiles, top talkers, protocol chart, traffic-over-time chart (Reqs 24–26);
  - HTTP: transactions table with the Req 28 columns, row click → stream inspector (Req 29);
  - Encrypted flows: table, inferred type and reasons;
  - Ask AI: skill selector, privacy notice, chat history per capture, evidence with links to transactions, warnings for invalid citations (Reqs 31–34);
  - Issues: parse and analysis warnings.
- Caching: `cache_resource` for the capture, `cache_data` for DataFrames
- Friendly error handling per tab (one failing view never blanks the page)
- Demo captures: the capture builders move from `tests/conftest.py` into `sniffdash.demo`, plus `python -m sniffdash.demo captures/`
- `requirements.txt` kept in sync with `pyproject.toml` (checked by a test); README "Run the dashboard" section
- Tests: facade unit tests, chart-builder tests, and `AppTest` UI tests

### Not building

- Authentication, multi-user deployment, persistent storage of uploads — PRD "What We're NOT Building"
- Live capture from a network interface — out of PRD scope
- PDF/report export — not required

## Delivery Considerations

| Concern | Decision and owned work |
|---|---|
| Large captures | A "max packets" sidebar option (default 200,000) feeds `ParserOptions.max_packets`; a spinner shows during parsing; partial results are labelled |
| Privacy | The Ask AI tab shows a one-line notice of what is sent to Google (from the README) before the first question |
| Missing key | The Ask AI tab explains how to add `GEMINI_API_KEY` instead of failing |
| New-user setup | `requirements.txt` + README: `pip install -r requirements.txt`, `python -m sniffdash.demo captures`, `streamlit run app.py` |

## Implementation

### 1. Demo captures as package data, shared with the tests

**Files and integration points**
- `src/sniffdash/demo.py` — CREATE — capture builders (`build_http_scenario`, `build_https_flows`, …) moved from `tests/conftest.py`, plus `write_demo_captures(directory)` and `python -m sniffdash.demo <dir>`
- `tests/conftest.py` — UPDATE — imports the builders from `sniffdash.demo` instead of defining them

**Implementation**
- A pure move: builder behavior is unchanged, so every existing expected value stays valid. Demo files are written to `captures/`, which is git-ignored.

**Tests**
- The existing suite stays green, which proves the move preserved behavior. A new test checks that `write_demo_captures` produces parseable files.

**Validation**
- `python -m pytest -q` — all pass; `python -m sniffdash.demo captures` writes 2 files.

### 2. `AnalysisSession` facade and bootstrap

**Files and integration points**
- `src/sniffdash/application/session.py` — CREATE — `load_capture(data, name, backend=None, max_packets=None) -> AnalysisSession`
- `src/sniffdash/application/bootstrap.py` — CREATE — `AppServices(settings, llm_service | None, llm_unavailable_reason)`

**Implementation**
- `load_capture` writes the bytes to a temporary file with the original suffix, parses it with `ParserFactory`, builds the repository, runs `AnalysisEngine`, and removes the temp file in `finally`.
- The facade exposes:
  - `summary`, `issues`, `parser_name`, `partial`;
  - DataFrame builders: `timeline_frame`, `protocol_frame`, `talkers_frame(direction)`, `transactions_frame` (Req 28 columns), `encrypted_frame`;
  - `stream(transaction_id)`, `transaction_for_frame(n)`;
  - `ask(question, level, service)`.
- `CaptureError` propagates as is; the UI shows its message.

**Tests**
- `tests/unit/test_session.py` on the demo capture:
  - the frames' columns and values (tx-4 row: GET, example.com, /index.html, 200, 120 ms, frames 4/5);
  - the stream lookup;
  - a garbage upload → `UnsupportedFormatError`;
  - the temp file is removed;
  - `ask` delegates to a `ScriptedClient`;
  - no key → `llm_unavailable_reason` set.

**Validation**
- `python -m pytest -q tests/unit/test_session.py` — all pass.

### 3. Chart builders (Req 26)

**Files and integration points**
- `src/sniffdash/ui/charts.py` — CREATE — `traffic_over_time(df, metric)`, `protocol_breakdown(df)`, `top_talkers(df)`: pure functions returning Plotly figures

**Implementation**
- Follows the dataviz skill's guidance (loaded before chart code): consistent palette, readable in light and dark themes, labelled axes and units, hover tooltips.
- Protocol breakdown is a sorted horizontal bar chart (the requirement allows pie or bar; bars compare categories more accurately).

**Tests**
- `tests/unit/test_charts.py`: each figure has the expected traces, axis titles and data, and handles an empty capture.

**Validation**
- `python -m pytest -q tests/unit/test_charts.py` — all pass.

### 4. Streamlit app: sidebar, caching, view registry, views

**Files and integration points**
- `app.py` (repo root) — CREATE — 3-line entry point: `from sniffdash.ui.app import main; main()`
- `src/sniffdash/ui/app.py` — CREATE — page config, settings, sidebar, cached load, tabs
- `src/sniffdash/ui/cache.py` — CREATE — `@st.cache_resource(max_entries=4)` capture loader; `@st.cache_data` frame helpers keyed by the capture fingerprint
- `src/sniffdash/ui/registry.py` — CREATE — `ResultView` ABC (`title`, `order`, `applies(session)`, `render(session, ctx)`) + `view_registry` (auto-discovered)
- `src/sniffdash/ui/views/{overview,http,encrypted,chat,issues}.py` — CREATE

**Implementation**
- **Sidebar:** `file_uploader` (pcap/pcapng/cap); a selectbox over the `captures/` folder (`SNIFFDASH_CAPTURE_DIR` overrides it); parser backend (auto / pyshark / scapy, showing which are available); max packets.
- **Tabs** are built from `view_registry` in `order`; each view renders inside its own error boundary.
- **HTTP:** row selection (`on_select="rerun"`, single row) drives the stream inspector, with request/response text in code blocks and the frame list. A selectbox fallback keeps it keyboard- and test-accessible.
- **Ask AI:**
  - skill-level `segmented_control`, privacy notice;
  - chat history in `st.session_state`, keyed by the capture fingerprint;
  - each answer shows its evidence table (frame, time, claim, and its transaction where one exists), invalid citations as warnings, and the tools used;
  - `LLMRateLimitError` / `LLMAuthError` / `LLMError` become friendly messages.
- Test hook: `st.session_state["sniffdash_llm_service"]` overrides the LLM service (used only by tests).

**Tests**
- `tests/ui/test_app.py` (`AppTest`, demo captures in a temp `captures/` folder):
  - no capture → welcome text;
  - picking the reference capture → 13 packets shown, 5 tabs;
  - HTTP tab table has 3 rows, and selecting tx-4 shows `GET /index.html` and `<html>hello</html>`;
  - Encrypted tab on the HTTPS demo shows 3 inferred types;
  - Ask AI with a scripted service → the answer and 2 valid evidence rows render;
  - no key → setup instructions;
  - garbage capture → friendly error, no exception.

**Validation**
- `python -m pytest -q tests/ui` — all pass.

### 5. Caching, extensibility and isolation guarantees

**Files and integration points**
- `tests/ui/test_caching.py`, `tests/unit/test_layering.py` — CREATE

**Implementation**
- **Caching:** rerunning the app (switching tabs, asking a question) must not call the parser again. This is proven with a parse counter monkeypatched into `load_capture` during `AppTest` runs.
- **Open/Closed:** a test-only `ResultView` registered into an isolated registry appears as a tab with no layout change.
- **Layering:** only `sniffdash/ui/**` imports `streamlit` (source scan, like the Phase 3 SDK-isolation test).

**Validation**
- `python -m pytest -q tests/ui/test_caching.py tests/unit/test_layering.py` — all pass.

### 6. Setup for new users

**Files and integration points**
- `requirements.txt` — CREATE — runtime dependencies plus pytest, mirroring `pyproject.toml`
- `pyproject.toml` — UPDATE — `streamlit>=1.40`, `plotly>=5.20`
- `README.md` — UPDATE — Quick start: install, demo captures, `streamlit run app.py`, screenshots of the flow
- `tests/unit/test_requirements_sync.py` — CREATE — fails if `requirements.txt` and `pyproject.toml` list different packages

**Validation**
- `python -m pytest -q tests/unit/test_requirements_sync.py` — passes.
- In a fresh virtualenv: `pip install -r requirements.txt` installs, and `streamlit run app.py` starts.

## Acceptance

1. **AC1 — Load (Req 23):** uploading or picking a `.pcap`/`.pcapng` loads it; non-captures and corrupt files show a friendly message, not a traceback; partial (truncated) captures are labelled.
2. **AC2 — Overview (Reqs 24–26):** packet count, start/end/duration, bytes, top source and destination IPs, the protocol chart and the traffic-over-time chart match the `AnalysisReport`.
3. **AC3 — HTTP table (Reqs 27–28):** one row per transaction with method, host, URI, source/destination IP:port, status, response time, and request/response frame numbers.
4. **AC4 — Stream inspection (Req 29):** selecting a transaction shows its request and response text and frame list.
5. **AC5 — Ask AI (Reqs 31–34):** questions return answers with validated evidence (frame + timestamp); invalid citations are visibly flagged; the skill level is selectable; a missing key or quota error shows guidance.
6. **AC6 — Encrypted flows:** flows are listed with inferred type and reasons.
7. **AC7 — Parse once:** reruns (tab switches, questions) do not re-parse an already loaded capture.
8. **AC8 — Open/Closed UI:** a new `ResultView` adds a tab without changing the layout code.
9. **AC9 — Layering:** only `sniffdash.ui` imports Streamlit; the facade and core stay framework-free.
10. **AC10 — Setup:** `requirements.txt` matches `pyproject.toml`; README quick start works; all earlier tests still pass.

## Validation

| Gate | Command or procedure | Proves |
|---|---|---|
| Focused behavior | `python -m pytest -q tests/unit/test_session.py tests/unit/test_charts.py tests/ui tests/unit/test_layering.py tests/unit/test_requirements_sync.py` | AC1–AC10 (automated parts) |
| Project gate | `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | AC10, no leaks |
| Portability | `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | AC10 on the Scapy path |
| Runtime / manual | `python -m sniffdash.demo captures` → `streamlit run app.py` → walk the User Flow, including one live question | Success signal; visual quality of the charts |

## Risks and Decisions

| Decision or risk | Recommendation | Evidence / mitigation | Consequence if different |
|---|---|---|---|
| Cache type for the capture | `cache_resource` (shared; immutable objects) | Phase 1–3 models are frozen; repository is read-only | `cache_data` would re-pickle the whole capture each rerun |
| Protocol chart form | Horizontal bar (pie allowed by the spec) | Bars compare categories more accurately | A pie is easy to add as a toggle if the course expects one |
| Default max packets | 200,000 | Keeps PyShark parsing in the tens-of-seconds range | Larger files are labelled partial; the user can raise the limit |
| AppTest coverage of row-click selection | Test through the selectbox fallback if AppTest cannot simulate `st.dataframe` selection | Probed: selectbox and chat_input drive fine | Row-click itself is then covered by the manual walkthrough |
| Moving capture builders into the package | Do it (single source for tests and demo) | Avoids duplicating 150 lines | Without it, the demo and the tests would drift apart |

## Self-Audit (pre-implementation, against Phases 1–3)

Requested by the user before implementation. Each gap is fixed in the design and owned by a task.

| ID | Gap | Fix | Task |
|---|---|---|---|
| A1 | Truncation (max packets) labelled in the UI but invisible to the AI; `AnalysisReport` had no partial flag | `AnalysisReport.partial`; context `capture.partial` + note; system-prompt rule; banner on every tab | 2, 4 |
| A2 | Chat-history key used the file bytes only | Fingerprint = SHA-256(bytes) + backend + max packets | 2, 4 |
| A3 | Error boundaries covered views but not loading | Load-level boundary with typed messages; failed loads never cached | 4, 5 |
| A4 | Absolute UTC only; Wireshark's default Time column is relative seconds | Tables show both `time (UTC)` and `rel. s` | 2 |
| A5 | Streamlit usage telemetry on by default; 200 MB upload cap | `.streamlit/config.toml`: `gatherUsageStats=false`, `maxUploadSize=500` | 4 |
| A6 | Empty states unspecified (0 packets, no HTTP, no TLS) | Explicit empty state per view; Encrypted tab hidden via `applies()` | 3, 4 |
| A7 | Chat failures could be recorded as answers or wipe history | Failed turns stored as failed, shown in-line, history preserved | 4 |
| A8 | `st.cache_resource` persists across `AppTest` runs | Fixture clears caches around every UI test | 4 |
| A9 | `max_entries=4` large repositories in RAM | `max_entries=2` | 4 |
| A10 | Evidence may cite non-HTTP frames | Link to the transaction when one exists, otherwise show frame metadata | 2, 4 |

Additional acceptance criteria from the audit:

11. **AC11 — Truncation is explicit everywhere:** a capture cut by the packet limit shows a banner on every tab, and the AI context carries `partial: true`.
12. **AC12 — Chat state:** history is kept per capture fingerprint (bytes + parser + limit); a failed question never erases history and is shown as failed.

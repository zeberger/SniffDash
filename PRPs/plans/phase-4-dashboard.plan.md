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

## Revision R1 — walkthrough feedback (2026-11-13, before PR #5)

The user's manual walkthrough found five problems. The user chose to fix them on this branch before PR #5 opens.

| ID | Feedback | Evidence (measured) |
|---|---|---|
| W1 | Chart labels are cryptic | Bar charts have no category-axis title (`yaxis.title = None`), the count axis says `packets`, and bytes mode says `B/s`. On the 0.5 s demo the timeline uses 10 ms buckets, so 2 packets in a bucket are shown as "200 packets/s" |
| W2 | Zoom suggests data that doesn't exist | Every axis has `fixedrange = None`, so Plotly allows zoom and pan beyond the capture's duration |
| W3 | Table headers are ambiguous | The "Table view" expander shows raw names (`rel_s`, `packets_per_s`, `share`, `ip`); HTTP uses `Rel. s`, `Req. frame`, `URI`; Encrypted leaves `client`, `server`, `bursts` raw; Issues and AI-evidence tables are unlabelled |
| W4 | Must not depend on specific Python/library versions | `pyproject.toml` already uses only lower bounds, but the bounds were **never tested**: everything ran only on Python 3.14 with the newest libraries |
| W5 | Ask AI is slow and allows too few questions | Live, "Which HTTP request was the slowest?": **19.9 s, 3 Gemini requests** (one 12 s call is model thinking; one request only fetched the response timestamp, which the context omits). With `thinking_level="low"`: **5.5 s, 2 requests**, same verified answer. A 504 from Google was not retried (`client.py:86` retries only 429/500/503) |

**Invariant (unchanged):** the UI only presents; every number still comes from the facade. New for this revision: **no raw
column name or unexplained abbreviation reaches the screen**, and **one question costs as few Gemini requests as the
data allows**.

### R1.1 Readable, non-zoomable charts (W1, W2)

**Files and integration points**
- `src/sniffdash/ui/charts.py` — UPDATE — titles, axis titles, fixed ranges
- `src/sniffdash/application/session.py:113` — UPDATE — `bucket_seconds` property, so the chart can say "per 10 ms"
- `src/sniffdash/ui/views/overview.py:13` — UPDATE — Plotly config without zoom/pan/select buttons

**Implementation**
- The timeline plots **counts per interval**, not per-second rates: title "Packets per 10 ms interval", y-axis "Packets in
  interval", x-axis "Time since capture start (s)". Bytes mode: "Bytes in interval". The interval label is formatted
  from `TrafficTimeline.bucket_seconds` (ms / s / min).
- Bar charts: category axis titled "Protocol (highest layer of each packet)" / "Source IP address" / "Destination IP
  address"; value axis "Number of packets"; the hover also shows the share. A caption explains that each packet counts
  once, under its highest protocol (so HTTP packets are not also counted as TCP).
- **Bounded zoom and pan (user decision, 2026-11-13):** the time axis keeps zoom-in and pan, but Plotly's
  `minallowed=0` / `maxallowed=duration` stop it at the capture's edges, so no view ever shows time outside the
  recording. The value axis and both bar-chart axes are `fixedrange`. **Dragging pans** (`dragmode="pan"`, user
  decision): zooming in is done with the mode-bar buttons or the scroll wheel, never with a drawn box. The mode bar
  keeps zoom in/out, reset and "Download as PNG"; box-zoom and box/lasso select are removed.
- **No clipped labels (user requirement):** category labels (protocols, full IP addresses) get their own space:
  `automargin=True` on every axis instead of the current fixed 8 px margins (`charts.py:32`), which cut long
  labels down to their last characters. Value labels printed beside bars get headroom: the value axis extends ~15%
  past the largest bar, so "1,234" is never cut at the right edge. Chart height grows with the number of bars
  (already `charts.py:74`).

**Tests**
- `tests/unit/test_charts.py`: every axis of every figure has a descriptive title (no bare unit); the time axis is
  bounded to exactly `[0, duration]` (`minallowed`/`maxallowed`) and every other axis is `fixedrange`; every axis has
  `automargin`; the bar value axis extends past the largest value; the interval label reads "10 ms" for the demo timeline.
- Manual walkthrough: long IPv6 / IPv4 labels and bar values fully visible, in light and dark mode.

**Validation**
- `python -m pytest -q tests/unit/test_charts.py` — passes, and fails on the current code.

### R1.2 Descriptive table headers (W3)

**Files and integration points**
- `src/sniffdash/ui/labels.py` — CREATE — one `column_config` per facade column (label + hover help), shared by all views,
  so a concept such as "Seconds since capture start" has one name everywhere
- `src/sniffdash/ui/views/{overview,http,encrypted,issues,chat}.py` — UPDATE — use it

**Implementation**
- Examples: `rel_s` → "Seconds since capture start"; `request_frame` → "Request frame #"; `source` → "Client (IP:port)";
  `bytes_down` → "Bytes server → client"; `bursts` → "Data bursts"; `share` → "Share of packets" (percent).

**Tests**
- `tests/unit/test_labels.py`: every column of every facade DataFrame (`timeline`, `protocols`, `talkers`,
  `transactions`, `encrypted`, `issues`, AI evidence) has a label and a help text. A new facade column without a label
  fails the test.

**Validation**
- `python -m pytest -q tests/unit/test_labels.py tests/ui` — passes.

### R1.3 Faster Ask AI with more questions per quota (W5)

**Files and integration points**
- `src/sniffdash/config.py` — UPDATE — `GEMINI_THINKING_LEVEL` (default `low`) and `GEMINI_FALLBACK_MODEL` (default
  `gemini-3.5-flash-lite`; checked with `models.list()` against the user's key on 2026-11-13); an empty value turns each off
- `src/sniffdash/llm/client.py:69-116` — UPDATE — thinking level in the request config; SDK retries for
  500/502/503/504 only; on 429 the client switches to the fallback model for 10 minutes; `active_model` property
- `src/sniffdash/llm/service.py:59` — UPDATE — on `LLMRateLimitError`, if the client switched model, restart the
  question from the first turn (one model's thought signatures can't be replayed to another); record the answering model
- `src/sniffdash/llm/answer.py:106` — UPDATE — `ValidatedAnswer.model`
- `src/sniffdash/llm/context.py:34-42` — UPDATE — index and "slowest" rows gain `resp_time`, so a question answered
  by the context needs one request instead of a lookup for the response timestamp
- `src/sniffdash/ui/views/chat.py:115` — UPDATE — the same question at the same level on the same capture reuses the
  stored answer (no request); the answer shows "answered by <model>"
- `.env.example`, `README.md` — UPDATE — document both settings

**Tests**
- `tests/unit/test_gemini_client.py` (fake SDK): `thinking_level` is sent; 429 → the next call uses the fallback model;
  no fallback configured → `LLMRateLimitError`; 429 is not in the SDK retry list, 504 is.
- `tests/unit/test_service.py` (`ScriptedClient`): a mid-question 429 with a fallback restarts from the first turn and
  succeeds; `model` is recorded.
- `tests/unit/test_context.py`: rows include `resp_time`.
- `tests/ui/test_app.py`: asking the same question twice calls the service once.

**Validation**
- `python -m pytest -q tests/unit/test_gemini_client.py tests/unit/test_service.py tests/unit/test_context.py tests/ui` — passes.
- Live (`-m live_llm`) on the demo: the reference questions still produce valid citations, with time and request count
  recorded in the report (target: the "slowest" question in 1 request, well under the 19.9 s baseline).

### R1.4 Proven version range instead of assumed (W4)

**User decision (2026-11-13):** run the matrix **locally before every push**, and keep it reusable for all later
phases (not a one-off check). GitHub Actions runs the same script as a second line of defence.

**Files and integration points**
- `scripts/version_matrix.py` — CREATE — the single matrix runner, used locally and by CI. For each cell it creates an
  isolated environment with `uv` (Python interpreters and packages go to `uv`'s cache under `%LOCALAPPDATA%\uv`;
  environments under the git-ignored `.matrix/`), installs `requirements.txt` at the cell's resolution, and runs the
  full pytest suite. Prints a pass/fail table; exit code 1 if any cell fails. `--python` / `--resolution` select one
  cell; `--clean` deletes `.matrix/`.
- Cells: **lowest** (every library at its declared minimum, `--resolution lowest-direct`) on Python 3.11, the oldest
  supported version; **highest** on Python 3.11, 3.12, 3.13, 3.14. Old library minimums have no wheels for new Python
  versions, so "oldest Python + oldest libraries" and "every Python + newest libraries" is the meaningful range.
- `.github/workflows/tests.yml` — CREATE — one job per cell, each calling `scripts/version_matrix.py`
- `pyproject.toml`, `requirements.txt` — UPDATE — `uv` added to the dev tools; raise any minimum that fails
- `README.md` — UPDATE — "Supported versions": how the range is defined, and the command to prove it
- `.gitignore` — UPDATE — `.matrix/`
- PRP process — every later phase's Validation table includes the matrix gate before push

**Implementation**
- The Streamlit 1.40 minimum is suspected too low (`width="stretch"`, `st.context.theme`); the lowest cell decides.
- No exact pins are added: ranges keep the project flexible, and the matrix proves that the range works.

**Validation**
- `python scripts/version_matrix.py` — every cell passes, before the push. After push: the workflow is green on the PR.

#### R1.4 status (2026-11-13): DEFERRED by the user to a later stage of the project

**Why deferring is safe:** a fresh `pip install -r requirements.txt` gets the newest libraries, which the regular
suite already covers (Python 3.14 + newest). Only machines with older versions already installed are affected.

**Findings so far.** The first run of the `lowest` cell (Python 3.11, every library at its declared minimum):
**25 failed, 366 passed**. Real minimums were found by bisection (install a candidate version, re-run the failing tests):

| Library | Declared | Real minimum | Why |
|---|---|---|---|
| numpy | `>=1.26` | `>=2.0` | Streamlit's current `pyarrow` refuses NumPy < 2.0 |
| pandas | `>=2.2` | `>=2.2.3` | 2.2.1 / 2.2.2 fail session and metrics tests under NumPy 2 |
| google-genai | `>=1.30` | `>=1.51` | `ThinkingConfig.thinking_level` (R1.3) appears in 1.51 |
| streamlit | `>=1.40` | not yet measured | |
| scapy | `>=2.5` | not yet measured | `test_malformed_packet_is_kept_and_reported[scapy]` fails on 2.5.0 |
| plotly | `>=5.20` | not yet measured | |

**Exact state at the pause point:**

| Item | State | Size |
|---|---|---|
| `pyproject.toml`, `requirements.txt` | **unchanged** (still the old, partly wrong minimums) | — |
| `scripts/version_matrix.py`, `.gitignore` (`.matrix/` entry) | committed with the R1.1–R1.3 checkpoint | — |
| `uv` 0.13.8 | installed in the project's `.venv` (`pip install uv`) | small |
| `.matrix\py3.11-lowest\` + `.log` | test environment, git-ignored; its packages were changed by the bisection (numpy 1.26.4, pandas 2.2.3, google-genai 1.51.0, streamlit 1.67.0) | 418 MB |
| `C:\Users\Lenovo\AppData\Roaming\uv\python\cpython-3.11…` | Python 3.11.18 downloaded by uv (not on PATH, not the system Python) | 70 MB |
| `C:\Users\Lenovo\AppData\Local\uv\cache` | uv's download cache | 802 MB |
| System Python 3.14, the project `.venv`'s other packages | **unchanged** | — |

**To undo the testing side effects (each deletion needs the user's two-step approval when run):**
1. `.\.venv\Scripts\python.exe scripts\version_matrix.py --clean` — deletes `.matrix\` (418 MB).
2. `.\.venv\Scripts\uv.exe python uninstall 3.11` — removes the downloaded Python 3.11 (70 MB).
3. `.\.venv\Scripts\uv.exe cache clean` — empties uv's cache (802 MB).
4. `.\.venv\Scripts\python.exe -m pip uninstall uv` — removes uv itself (run last: steps 2–3 need it).
5. Optional, repository: delete `scripts/version_matrix.py` and the `.matrix/` lines in `.gitignore` on a new branch.
   Keeping them is harmless; they do nothing unless run.

Nothing else needs undoing: no project source or dependency file was changed by the testing.

**To resume (from this exact point):**
1. If step 4 above was done: `.\.venv\Scripts\python.exe -m pip install uv`.
2. Apply the three measured minimums in `pyproject.toml` and `requirements.txt`: `numpy>=2.0`, `pandas>=2.2.3`, `google-genai>=1.51`.
3. `.\.venv\Scripts\python.exe scripts\version_matrix.py --resolution lowest` — rebuilds `.matrix\py3.11-lowest` from
   scratch, so the hand-modified environment doesn't matter. Python 3.11 and packages are re-downloaded if steps 2–3 were done.
4. For each remaining failure, bisect that library (streamlit, scapy, plotly) the same way, raise its minimum, repeat 3.
5. `.\.venv\Scripts\python.exe scripts\version_matrix.py` — all five cells, including the four `highest` ones.
6. Add `.github/workflows/tests.yml` (one job per cell, calling the script) and the README "Supported versions" section.
7. AC18 closes when every cell passes locally and on GitHub.

### Acceptance (R1)

13. **AC13 — Readable charts:** every chart axis has a descriptive title, the timeline names its interval width, and
    no label or value is clipped.
14. **AC14 — No phantom ranges:** zoom and pan never leave the capture's time span; bar charts don't move.
15. **AC15 — Readable tables:** every table column shown has a descriptive header and a hover explanation.
16. **AC16 — Faster AI:** the reference "slowest request" question is answered with valid citations faster than the
    19.9 s baseline, using fewer requests; a repeated question uses none.
17. **AC17 — Quota resilience:** when the main model's quota is exhausted, questions continue on the fallback model, and
    the answer says which model answered.
18. **AC18 — Version range proven:** the test suite passes on Python 3.11–3.14 with both the minimum and the newest
    allowed library versions.

### Validation (R1)

| Gate | Command or procedure | Proves |
|---|---|---|
| Focused | `python -m pytest -q tests/unit/test_charts.py tests/unit/test_labels.py tests/unit/test_gemini_client.py tests/unit/test_service.py tests/unit/test_context.py tests/ui` | AC13–AC17 (automated) |
| Project | `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | No regressions |
| Live AI | `python -m pytest -q -m live_llm` + timed reference question | AC16, AC17 against the real model |
| Version matrix | `python scripts/version_matrix.py` before push; then GitHub Actions on the PR | AC18 |
| Manual | `streamlit run app.py` walkthrough of charts and tables | AC13–AC15 visual quality |

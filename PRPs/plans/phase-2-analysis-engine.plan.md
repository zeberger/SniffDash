# Compute capture metrics and paired HTTP transactions from the frame repository

**Plan ID:** `phase-2-analysis-engine`
**Source PRD:** `PRPs/prds/sniffdash.prd.md`
**PRD Phase:** `2 — Analysis engine`
**Source Issue:** `None`

## Outcome

**Problem:** Phase 1 delivers raw frames. Modules 1–2 need global metrics, a traffic timeline, and HTTP requests
paired with their responses (with response times and frame numbers), plus the data behind "Follow HTTP Stream".
None of this exists yet.

**Affected user:** The student or grader viewing a capture (through Phase 4's UI), and Phase 3's AI layer, which
answers questions from the same results.

**User outcome:** One call turns a `FrameRepository` into an `AnalysisReport` containing the capture summary, a
traffic timeline, and every HTTP transaction, each with method, host, URI, endpoints, status, response time, and
request/response frame numbers. Any transaction can be expanded into its full request/response text.

**Invariant:** A response is paired only with a request on the **same TCP connection**, travelling in the
**opposite direction**, and in **request order** (HTTP/1.1, RFC 9112 §9.3.2). The pairing result is identical
whichever parser produced the frames.

**Success signal:** Not measured separately — acceptance against the reference and pipelined captures, whose
correct answers are known exactly, fully captures this internal outcome.

**Approach:** One `Analyzer` strategy interface and an auto-discovering registry (the same pattern as Phase 1's
extractors). Built on it: a mandatory `SummaryAnalyzer`, a `TimelineAnalyzer`, and an `HttpAnalyzer` that builds
domain messages from the normalized `http` layer and pairs them per TCP stream in FIFO order. An `AnalysisEngine`
runs them all with per-analyzer fault isolation. `HttpStreamReconstructor` renders one transaction as Follow-Stream text.

## Recommendation

Pair HTTP messages with **one** backend-independent rule: per TCP stream, each final response answers the oldest
unanswered request sent in the opposite direction. This is exactly HTTP/1.1's ordering guarantee. The architecture
originally proposed trusting tshark's `request_in`/`response_in` links first, with FIFO as a fallback. The probe below
shows those links are wrong for pipelined requests, so the composite strategy would add machinery *and* produce wrong
pairs. Dropping it removes a strategy class, a composition layer, and a parity risk between the backends.

Metrics are computed from the repository's existing DataFrame view (`to_dataframe()`) with Pandas, rather than by
looping over frames, so the work stays in one vectorized place per metric.

### Evidence

- **Pipelining probe** (tshark 4.6.9, 2 requests → 2 responses on one connection): tshark linked response #6
  (answering `/a`) to request #5 (`/b`), and left request #4 and response #7 unpaired. Scapy provides no links at all.
  FIFO per stream pairs both correctly on both backends.
- `src/sniffdash/parsing/extractors/base.py:1-30` — normalized `http` layer schema (`kind`, `method`, `uri`, `host`,
  `status_code`, `reason`, `headers`, `body`): everything pairing needs is backend-neutral.
- `src/sniffdash/domain/models.py:172-230` — `HttpRequest`, `HttpResponse`, `HttpTransaction` (with
  `response_time_ms`) already exist and are tested. `HttpTransaction` rejects a response that precedes its request.
- `src/sniffdash/domain/results.py:50-115` — `CaptureSummary`, `HttpAnalysisResult` (with `unanswered`,
  `find_by_frame`), and `AnalysisReport.get(type)` already define the output contract.
- `src/sniffdash/repository/base.py:26-75` — `iter(protocol)`, `by_stream(transport, id)`, `to_dataframe()` provide
  every access path needed; no new repository method is required.
- `src/sniffdash/parsing/extractors/base.py:65-95` — `ExtractorRegistry._discover` is the auto-discovery precedent
  to reuse for analyzers.

### Alternatives considered

- **tshark links first, FIFO fallback (original design):** wrong pairs on pipelined traffic (probe above), and
  different results per backend, which breaks the invariant.
- **Separate `MetricCalculator` class per metric:** a second strategy layer feeding one `CaptureSummary`. It adds
  indirection without a new extension point; each metric is a few lines of Pandas inside the analyzer that owns the result.

## Visuals

```
FrameRepository ──► AnalysisEngine.run(repo)
                      ├─ SummaryAnalyzer   (mandatory) ──► CaptureSummary          → AnalysisReport.summary
                      └─ registry analyzers (isolated):
                           ├─ TimelineAnalyzer        ──► TrafficTimeline        ┐
                           └─ HttpAnalyzer                                        ├► AnalysisReport.results[key]
                                messages.py  frame.http layer → HttpRequest/Response
                                pairing.py   per (tcp stream): FIFO, opposite direction, skip 1xx (except 101)
                                             ──► HttpAnalysisResult(transactions, orphan_responses)   ┘
HttpStreamReconstructor(tx, repo) ──► HttpStreamView(request_text, response_text, frame numbers)
```

## Implementation Context

### Mandatory reading

| File | Why it matters |
|---|---|
| `src/sniffdash/domain/results.py:43-115` | Result types to fill; `AnalysisResult.key` is how the UI and the LLM look results up |
| `src/sniffdash/domain/models.py:149-230` | HTTP models and their validation (status range, response-before-request) |
| `src/sniffdash/parsing/extractors/base.py:1-95` | `http` layer schema; registry discovery to reuse |
| `src/sniffdash/repository/in_memory.py:16-25` | `FRAME_COLUMNS`: the DataFrame the metrics read |
| `tests/conftest.py` | Reference scenario (13 frames) and the capture-building helpers the new fixtures reuse |

### Existing patterns and primitives

- **Registry + auto-discovery:** `src/sniffdash/parsing/extractors/base.py:65-95`. Extract the module-import loop into a
  shared helper, so both registries use it instead of duplicating it.
- **Notification pattern:** `ParseIssue` (`src/sniffdash/domain/errors.py:93`). Analyzer failures and skipped
  messages become issues in `AnalysisReport.issues`.
- **Fault isolation:** `PacketParser.parse` (`src/sniffdash/parsing/base.py:81-130`) is the precedent: one bad unit
  produces an issue, never an aborted run.

### Integration points

- `AnalysisReport` (`src/sniffdash/domain/results.py:102`) is consumed by Phase 3 (LLM context) and Phase 4 (UI).
- `AnalysisError` (`src/sniffdash/domain/errors.py:60`) is raised only when the mandatory summary cannot be built.

## Scope

### In scope

- `Analyzer` interface, analyzer registry, `AnalysisEngine` with fault isolation
- Capture summary: packet count, total bytes, start/end/duration, top-N source and destination IPs, protocol distribution
- Traffic timeline: packets and bytes per time bucket, with an automatic bucket size and empty buckets kept
- HTTP message building, FIFO pairing per TCP stream, unanswered requests, orphan responses
- Follow-HTTP-Stream reconstruction for one transaction
- Unit and integration tests, including a pipelined capture fixture

### Not building

- Charts, tables and other UI — Phase 4
- LLM context and tools — Phase 3 (they read this phase's `AnalysisReport`)
- DNS/TLS analyzers — future assignments; the registry makes them additive
- HTTP/2 and pipelined messages sharing one TCP segment — out of PRD scope / Phase 1 documented limitation

## Implementation

### 1. Shared plugin discovery

**Files and integration points**
- `src/sniffdash/plugins.py` — CREATE — `import_submodules(package: str, skip: set[str])`, the one owner of discovery
- `src/sniffdash/parsing/extractors/base.py:86-95` — UPDATE — `_discover` delegates to the helper

**Implementation**
- Move the `pkgutil.iter_modules` loop into the helper.
- **Fix a concurrency race (found in review):** `_discover` currently sets `_discovered = True` *before* importing. Under Streamlit, two sessions parsing at the same moment can make the second thread see a half-filled registry and silently skip extractors. Guard discovery with a `threading.Lock` and set the flag only after all imports succeed.

**Tests**
- Existing `tests/unit/test_extractors.py::TestRegistry` stays green.
- New: 8 threads call `create_all` on a fresh registry at once, and all of them get the complete extractor list.

**Validation**
- `python -m pytest -q tests/unit/test_extractors.py` — all pass.

### 2. Analyzer contract, registry and engine

**Files and integration points**
- `src/sniffdash/analysis/base.py` — CREATE — `Analyzer` ABC (`key`, `analyze(repo) -> AnalysisResult`), `AnalysisOptions` (`top_n=10`, `max_timeline_buckets=200`), `AnalyzerRegistry` + `analyzer_registry` (discovers `sniffdash.analysis.analyzers`)
- `src/sniffdash/analysis/engine.py` — CREATE — `AnalysisEngine(summary=None, analyzers=None, options=None)`, `run(repo, *, source="", issues=()) -> AnalysisReport`

**Implementation**
- The engine always runs the summary analyzer, and raises `AnalysisError` if it fails, because a report without a summary is meaningless.
- Each registry analyzer runs in isolation: an exception becomes an ERROR `ParseIssue("Analyzer '<key>' failed: …")`, its result is omitted, and the others continue.
- Parse issues passed in are kept in the report ahead of analysis issues. Analyzers can add issues through an `AnalysisContext` collector passed to `analyze`.
- Analyzers and options can be injected for tests (DI, as in Phase 1's `PacketParser(extractors=…)`).

**Tests**
- `tests/unit/test_engine.py`: a failing analyzer is isolated; a failing summary raises `AnalysisError`; built-in analyzers are auto-discovered; a new analyzer registers without core edits.

**Validation**
- `python -m pytest -q tests/unit/test_engine.py` — all pass.

### 3. Capture summary and traffic timeline (Reqs 24–26 data)

**Files and integration points**
- `src/sniffdash/analysis/analyzers/summary.py` — CREATE — `SummaryAnalyzer` → `CaptureSummary`
- `src/sniffdash/analysis/analyzers/timeline.py` — CREATE — `TimelineAnalyzer` → `TrafficTimeline`
- `src/sniffdash/domain/results.py` — UPDATE — add `TrafficTimeline(AnalysisResult)`, key `"timeline"`: `bucket_seconds`, `buckets: tuple[(start_ts, packets, bytes), …]`

**Implementation**
- Computed from `repo.to_dataframe()`.
- Top-N IPs are counted by packets, with ties broken by IP for deterministic output; frames without IP are excluded.
- Protocol distribution counts `highest_protocol` (one bucket per frame, so the slices sum to the packet count).
- Bucket size is the smallest value on the ladder 1 ms, 10 ms, 100 ms, 1 s, 10 s, 1 min, 10 min, 1 h that yields ≤ `max_timeline_buckets`. Empty buckets are kept so the chart shows silences.
- An empty capture gives zero counts, `None` start/end, and an empty timeline (no exception).

**Tests**
- `tests/unit/test_metrics.py` with hand-made frames: counts, bytes, duration, top-N order and ties, protocol sums, bucket selection, zero-filled gaps, empty repository.

**Validation**
- `python -m pytest -q tests/unit/test_metrics.py` — all pass.

### 4. HTTP transactions (Reqs 27–28)

**Files and integration points**
- `src/sniffdash/analysis/analyzers/http/messages.py` — CREATE — `build_messages(repo, ctx) -> list[HttpRequest | HttpResponse]`
- `src/sniffdash/analysis/analyzers/http/pairing.py` — CREATE — `pair_by_stream(messages) -> (transactions, orphans)`
- `src/sniffdash/analysis/analyzers/http/analyzer.py` — CREATE — `HttpAnalyzer` → `HttpAnalysisResult`

**Implementation**
- **Messages:** take only frames whose `http.kind` is request/response, including any `extra_messages` (Task 6). If a message cannot become a domain model (missing method, status outside 100–599), skip it with a WARNING naming the frame.
- **Retransmission de-duplication:** a message whose `(stream_id, src endpoint, TCP seq)` was already seen is a retransmission. Skip it with an INFO issue; otherwise it would sit in the queue as a ghost request and shift every later pairing on that connection.
- **Pairing, with the stream ID taking precedence:** partition messages by `(Transport.TCP, stream_id)` first. FIFO ordering applies only *inside* one stream, so a response can never be matched across connections, however dense or interleaved the traffic. A message without a stream ID is skipped with a WARNING. (True HTTP/2 multiplexing is out of scope. HTTP/1.1 "parallelism" means separate TCP connections, which this partitioning keeps apart.)
- **Pairing steps:** walk each stream in frame order. A request joins its stream's pending queue. A final response (status ≥ 200, or 101) pops the oldest pending request whose `dst` equals the response's `src`.
  - Interim 1xx responses (100/102/103) are attached to nothing and do not consume the request.
  - A response with nothing pending is an orphan.
  - A response timestamped before its request is treated as an orphan with a WARNING, so a pairing anomaly never crashes the analysis.
- Transaction id: `tx-<request frame number>`. Transactions are sorted by request frame.
- Response time follows Wireshark's `http.time` definition: the timestamp of the frame carrying the parsed response minus the request's. tshark places the HTTP layer on the last segment after reassembly, so for multi-segment responses the backends can differ (documented).

**Tests**
- `tests/unit/test_http_pairing.py` with hand-made messages: sequential, pipelined, interleaved streams, wrong direction, orphan, 100-Continue then 200, response before request.
- `tests/integration/test_analysis_reference.py` (both backends): the reference capture yields exactly 3 transactions:
  - `tx-4` GET `/index.html` → 200, frames 4→5, 120 ms;
  - `tx-6` GET `/missing` → 404, frames 6→7, 60 ms;
  - `tx-13` POST `/api/login` unanswered.

  A new pipelined capture fixture pairs `/a`→200 and `/b`→404 on **both** backends (the case tshark's own links get wrong).

**Validation**
- `python -m pytest -q tests/unit/test_http_pairing.py tests/integration/test_analysis_reference.py` — all pass.

### 5. Follow HTTP Stream (Req 29 data)

**Files and integration points**
- `src/sniffdash/analysis/analyzers/http/stream.py` — CREATE — `HttpStreamReconstructor.reconstruct(tx, repo) -> HttpStreamView`
- `src/sniffdash/domain/results.py` — UPDATE — `HttpStreamView`: `transaction`, `request_text`, `response_text`, `frame_numbers` (every frame of that TCP stream from the request through the response)

**Implementation**
- Request text = request line + headers + blank line + body. Response text = status line + headers + body, or "(no response captured)".
- Frames come from `repo.by_stream(Transport.TCP, stream_id)`, bounded by the request and response frame numbers.

**Tests**
- Reference `tx-4`: the text contains `GET /index.html HTTP/1.1`, `Host: example.com` and `<html>hello</html>`, and the frames are `(4, 5)`. The unanswered `tx-13` produces placeholder response text.

**Validation**
- `python -m pytest -q tests/integration/test_analysis_reference.py -k stream` — passes.

### 6. Stream-bound hardening in the parsing layer (review findings, probe-verified)

**Files and integration points**
- `src/sniffdash/parsing/scapy_parser.py:32-46` — UPDATE — `StreamIndexer`
- `src/sniffdash/parsing/extractors/http.py:31-70` — UPDATE — `PySharkHttpExtractor`
- `src/sniffdash/parsing/extractors/base.py:1-30` — UPDATE — schema doc: `http.extra_messages`

**Implementation**
- **Port reuse:** the probe showed tshark gives a reused 4-tuple a new stream (`s1`), while Scapy merged it into `s0`. An unanswered request on the old connection could then steal the new connection's response. Fix: a pure SYN (SYN without ACK) on an already-known 4-tuple opens a new stream index.
- **Two HTTP messages in one segment:** the probe showed both backends kept only the first of two pipelined responses, so `/b` looked unanswered and any later response would shift onto it. Fix: PyShark reads every HTTP layer (`packet.get_multiple_layers("http")`); the first stays the `http` layer, and the rest go to `extra_messages` with the same schema. Scapy cannot split them; this is documented as a fallback limitation.

**Tests**
- New capture fixtures for port reuse, retransmission and two-in-one-segment:
  - port reuse: identical stream IDs and transactions on both backends;
  - retransmission: one transaction, no ghost;
  - two-in-one-segment: `/a`→200 and `/b`→404 with PyShark, and the documented Scapy behavior asserted explicitly.

**Validation**
- `python -m pytest -q tests/integration/test_stream_bounds.py` — all pass.

### 7. Cache-ready analysis output

**Files and integration points**
- `src/sniffdash/analysis/engine.py` — the engine stays a pure function of its input: no hidden state, deterministic ordering

**Implementation**
- Streamlit's `@st.cache_data` stores return values by *pickling* them and hands each rerun a fresh copy. So everything the cached function returns (`ParseOutcome`, `AnalysisReport`, `TrafficTimeline`, `HttpStreamView`, DataFrames) must pickle losslessly, and the same input must give the same output.
- The decorator itself is applied in Phase 4's application layer, on one function `load_and_analyze(file_bytes)`, so parsing and analysis run once per distinct file. The core layers stay Streamlit-free, which is the layering rule from the architecture, and remain testable without a UI. The repository object goes in `@st.cache_resource` (shared, not copied), which is safe because all models are immutable. These are recorded in the PRD's Phase 4 scope.

**Tests**
- `AnalysisReport` from the reference capture survives a pickle round trip unchanged.
- Two runs on the same capture produce equal reports.

**Validation**
- `python -m pytest -q tests/integration/test_analysis_reference.py -k "pickle or deterministic"` — passes.

## Acceptance

1. **AC1 — Summary:** the reference capture reports 13 packets, a start/end matching frames 1 and 13, a 0.5 s duration, top source `10.0.0.2`, and a protocol distribution summing to 13.
2. **AC2 — Timeline:** buckets sum to the packet and byte totals; empty intervals appear as zero buckets; bucket count ≤ `max_timeline_buckets`.
3. **AC3 — Pairing correctness:** the reference capture yields exactly `tx-4` (200, 120 ms), `tx-6` (404, 60 ms) and `tx-13` (unanswered), with correct method, host, URI, endpoints and frame numbers.
4. **AC4 — Pipelining:** pipelined requests on one connection are paired in request order on both backends.
5. **AC5 — Backend independence:** PyShark and Scapy produce identical transaction lists for both captures.
6. **AC6 — Robust pairing:** orphan responses, interim 1xx responses, wrong-direction responses and malformed HTTP messages produce issues or orphans, never exceptions.
7. **AC7 — Fault isolation:** a failing analyzer yields an ERROR issue and a report without that result, while the other results are present.
8. **AC8 — Stream view:** any transaction reconstructs into request/response text plus its frame numbers.
9. **AC9 — Extensibility:** a new analyzer module in `analysis/analyzers/` is picked up with no change to the engine or registry code.
10. **AC10 — Phase 1 preserved:** the full Phase 1 suite still passes.
11. **AC11 — Stream isolation:** a response is never paired across TCP streams. Port reuse produces separate streams, with identical stream IDs on both backends.
12. **AC12 — Retransmissions:** a retransmitted HTTP message never creates an extra request or shifts later pairings.
13. **AC13 — Multi-message segments:** with PyShark, every HTTP message in one segment is paired. The Scapy behavior is documented and asserted.
14. **AC14 — Concurrency and caching:** plugin discovery is thread-safe, and the `AnalysisReport` is picklable and deterministic.

## Validation

| Gate | Command or procedure | Proves |
|---|---|---|
| Focused behavior | `python -m pytest -q tests/unit/test_metrics.py tests/unit/test_http_pairing.py tests/unit/test_engine.py tests/integration/test_analysis_reference.py tests/integration/test_stream_bounds.py` | AC1–AC9, AC11–AC14 |
| Project gate | `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | AC10, no leaks |
| Portability | `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | AC5 on the Scapy-only path |

## Risks and Decisions

| Decision or risk | Recommendation | Evidence / mitigation | Consequence if different |
|---|---|---|---|
| Drop tshark-link pairing | FIFO per stream only | Pipelining probe: tshark links mispair | Keeping tshark-first would mispair pipelined traffic and differ per backend |
| Top-N default | 10 | Readable chart; configurable in `AnalysisOptions` | Larger N clutters Phase 4 charts and the LLM context |
| Multi-segment response time differs by backend | Accept and document | Scapy has no reassembly (Phase 1 limitation) | Only affects responses split across segments with the Scapy fallback |
| Malformed header lines (no colon) | Keep dropping them silently, as Phase 1 does | Request/status-line errors already produce WARNINGs; a junk header line cannot affect pairing | Surfacing every junk line would flood the issue list |
| Request never answered (capture ended, connection reset) | Report as unanswered; never guess | `HttpTransaction.response = None`, shown in the table | Inventing a timeout-based "response" would fabricate evidence |
| Lazy DataFrame build in the repository under concurrent sessions | Accept | Both threads would build identical data; frames are immutable | Adding a lock costs complexity for no correctness gain |

## Agent Notes

The PRD's Phase 2 description and Decisions Log were updated to record the FIFO-per-stream decision and its probe evidence.

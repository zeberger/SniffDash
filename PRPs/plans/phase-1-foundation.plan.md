# Turn a capture file into an immutable, indexed frame repository

**Plan ID:** `phase-1-foundation`
**Source PRD:** `PRPs/prds/sniffdash.prd.md`
**PRD Phase:** `1 — Foundation`
**Source Issue:** `None`
**Plan Publication:** `None`

## Outcome

**Problem:** Every SniffDash feature (metrics, HTTP pairing, AI answers, UI) needs trustworthy frame data, but capture
files come in several formats, may be truncated or contain malformed packets, and the two available parsing libraries
expose incompatible packet objects.

**Affected user:** Phases 2–4 of SniffDash, and through them the student or grader who uploads a capture.

**User outcome:** Any `.pcap`/`.pcapng` file becomes an immutable, indexed set of `Frame` objects whose numbers match
Wireshark's "No." column, whichever backend is installed.

**Invariant:** A frame's `number` always equals its Wireshark frame number. It is never renumbered, even when an earlier
packet fails to decode, because AI citations (Req 34) depend on it.

**Success signal:** Not measured separately — this is an internal foundation. Acceptance, especially backend parity
(AC5) and failure handling (AC2–AC4), fully captures its value.

**Approach:** A stdlib-only domain layer; a Template Method `PacketParser` that owns all failure rules, with PyShark and
Scapy adapters selected by a `ParserFactory`; per-protocol extractors found through an auto-discovering registry; and a
read-only `FrameRepository` with prebuilt indexes and a lazy Pandas view.

## Recommendation

Put the robustness rules (skip a bad packet, keep partial results, typed errors) in one Template Method,
`PacketParser.parse`, so both backends inherit identical behavior instead of each re-implementing it. Normalize all
backend output through one `FrameAssembler` and one documented layer schema, so analysis code never sees PyShark or
Scapy types. Detect format and truncation from file structure (`formats.py`) before any backend runs, which makes those
errors backend-independent.

### Evidence

- tshark 4.6.9 probe: HTTP header lines arrive as repeated `request_line` / `response_line` fields; bodies arrive as
  colon-hex `file_data`; `response_in` on a request is populated only with two-pass analysis (`-2`).
- pyshark 0.6 `capture.py:86-88` — an explicit `eventloop` skips pyshark's global-loop setup, which Streamlit worker
  threads lack.
- Scapy 2.8 has no `tcp.stream` equivalent and no TCP reassembly, so stream indexes must be computed
  (`StreamIndexer`) and HTTP split across segments is out of reach for the fallback.

### Alternatives considered

- **Scapy only:** no Wireshark dependency, but no reassembly, no TLS, and no request↔response hints, so it is weaker for Module 2.
- **Per-backend error handling:** duplicates the failure rules, and the backends drift apart (fails the parity invariant).
- **`types.MappingProxyType` for frozen layers:** not picklable, which would break `st.cache_data` in Phase 4.

## Visuals

```
file ──► formats.scan_integrity ──► ParserFactory.create ──► PacketParser.parse (Template Method)
              │  typed errors              │ PyShark | Scapy          │ per packet:
              ▼                            ▼                          │   _read_meta → extractors → _post_process
      CaptureError family          ParserUnavailableError             │   → FrameAssembler → Frame
                                                                      ▼
                                       ParseOutcome(frames, issues, partial) ──► InMemoryFrameRepository
```

## Implementation Context

### Mandatory reading

| File | Why it matters |
|---|---|
| `src/sniffdash/parsing/base.py:81-145` | The Template Method: every failure rule lives here |
| `src/sniffdash/parsing/extractors/base.py:1-30` | The normalized layer schema, which is the contract with Phase 2 |
| `src/sniffdash/domain/models.py:91-130` | `Frame` invariants (number ≥ 1, deep immutability) |
| `tests/conftest.py:1-25` | The 13-frame reference scenario that every expected value comes from |

### Existing patterns and primitives

- **Registry with auto-discovery:** `src/sniffdash/parsing/extractors/base.py:65-95` — `@extractor_registry.register(Backend.X)`; modules found with `pkgutil`.
- **Notification pattern:** `src/sniffdash/domain/errors.py:93` — `ParseIssue` collected in `ParseOutcome.issues` instead of raising.

### Integration points

- `src/sniffdash/repository/base.py:26` — `FrameRepository` is the only data source Phase 2 analyzers may use.
- `src/sniffdash/domain/results.py:43-115` — `AnalysisResult`, `CaptureSummary`, `HttpAnalysisResult`, `AnalysisReport` are declared here for Phase 2 to fill.

## Scope

### In scope

- Domain models, results and error hierarchy
- Format detection, integrity scan, parser factory, PyShark and Scapy backends
- ip/tcp/udp/http/dns/tls extractors, frame assembly
- Frame repository and its DataFrame view
- Unit and integration tests, including backend parity

### Not building

- Metrics, HTTP pairing, stream reconstruction — Phase 2
- `.env` loading / configuration object — Phase 4 bootstrap (`TSHARK_PATH` works as a real environment variable now)
- Scapy TLS dissection — needs the optional `cryptography` dependency; documented fallback limitation
- Extraction of a second pipelined HTTP message in one TCP segment — rare; documented limitation

## Implementation

### 1. Immutable, picklable domain model

**Files and integration points**
- `src/sniffdash/domain/models.py` — CREATE — owns `Frame`, `Endpoint`, `FrozenMap`, HTTP models
- `src/sniffdash/domain/results.py` — CREATE — owns `ParseOutcome` and the analysis result types
- `src/sniffdash/domain/errors.py` — CREATE — owns the `SniffDashError` hierarchy and `ParseIssue`

**Implementation**
- Frozen slots dataclasses; `Frame.__post_init__` rejects number < 1 and negative length, lowercases protocols, and deep-freezes `layers`.
- `FrozenMap` implements `__reduce__` so frames survive pickling.
- `HttpTransaction.response_time_ms` = (response − request) × 1000; `None` when unanswered; a response earlier than its request is rejected.

**Tests**
- `tests/unit/test_models.py`, `tests/unit/test_results_and_errors.py`

**Validation**
- `python -m pytest -q tests/unit/test_models.py tests/unit/test_results_and_errors.py` — all pass.

### 2. Format detection and integrity scan

**Files and integration points**
- `src/sniffdash/parsing/formats.py` — CREATE — owns structural checks so they are backend-independent

**Implementation**
- Detect by magic bytes: pcap LE/BE, nanosecond pcap, pcapng; reject empty, short and unknown files with typed errors.
- Walk pcap record headers / pcapng block lengths without reading payloads; report complete records and truncation; reject impossible lengths.

**Tests**
- `tests/unit/test_formats.py` with byte-exact handcrafted files.

**Validation**
- `python -m pytest -q tests/unit/test_formats.py` — all pass.

### 3. Backend-neutral extraction

**Files and integration points**
- `src/sniffdash/parsing/extractors/` — CREATE — `base.py` (Strategy ABC, registry, helpers) and `ip.py`, `tcp_udp.py`, `http.py`, `dns.py`, `tls.py`
- `src/sniffdash/parsing/assembler.py` — CREATE — owns endpoints, stream id and highest-protocol rules

**Implementation**
- One extractor per protocol per backend, all producing the schema documented at `extractors/base.py:1-30`.
- `FrameAssembler.highest_protocol` skips payload formats (e.g. `data-text-lines`), so HTML responses count as `http`.

**Tests**
- `tests/unit/test_extractors.py` (helpers, discovery, OCP registration, assembler)

**Validation**
- `python -m pytest -q tests/unit/test_extractors.py` — all pass.

### 4. Parsing pipeline with two interchangeable backends

**Files and integration points**
- `src/sniffdash/parsing/base.py` — CREATE — Template Method `parse`
- `src/sniffdash/parsing/pyshark_parser.py`, `scapy_parser.py`, `tshark_locator.py`, `options.py` — CREATE
- `src/sniffdash/parsing/factory.py` — CREATE — backend selection by priority and availability

**Implementation**
- `parse` catches per-packet and per-layer failures as WARNING issues, keeps frames after a backend crash (`partial=True`), and raises `CorruptCaptureError` only when nothing was parsed.
- PyShark: private event loop, two-pass `-2`, idempotent `close()`, tshark's `_ws.malformed` → WARNING.
- Scapy: `StreamIndexer` reproduces `tcp.stream` numbering; layer names map to Wireshark names.
- Factory: AUTO picks the first available backend; an explicitly requested missing backend raises `ParserUnavailableError`.

**Tests**
- `tests/unit/test_parser_template.py` (fake backend), `tests/unit/test_factory.py` (stub availability)
- `tests/integration/test_parsing_backends.py` (both backends, parametrized), `tests/integration/test_pyshark_specifics.py` (tshark hints, parity)
- `tests/integration/test_edge_cases.py` (TLS ClientHello, malformed DNS through real backends)

**Validation**
- `python -m pytest -q tests/integration` — all pass with tshark; PyShark cases skip without it.

### 5. Read-only indexed repository

**Files and integration points**
- `src/sniffdash/repository/base.py`, `in_memory.py` — CREATE — the data-access contract for Phase 2

**Implementation**
- Indexes by number, protocol and (transport, stream) built once; `time_range` uses min/max; DataFrame built lazily, copied on return, nullable `Int64` ports.

**Tests**
- `tests/unit/test_repository.py`

**Validation**
- `python -m pytest -q tests/unit/test_repository.py` — all pass.

## Acceptance

1. **AC1 — Format detection:** pcap (µs and ns variants) and pcapng are recognized by magic bytes regardless of file extension.
2. **AC2 — Typed rejection:** empty or non-capture files raise `CorruptCaptureError` / `UnsupportedFormatError`, never a raw traceback.
3. **AC3 — Truncation:** a truncated capture returns its readable frames with `partial=True` and an ERROR issue.
4. **AC4 — Packet isolation:** a packet that fails to decode, or that a real dissector flags as malformed, produces a WARNING naming its frame number; parsing continues and numbering is preserved.
5. **AC5 — Backend parity:** PyShark and Scapy yield identical frame numbers, timestamps, lengths, endpoints, transports, stream ids, highest protocols and HTTP request fields for the reference capture.
6. **AC6 — Fallback:** without tshark, AUTO selects Scapy; an explicit request for a missing backend raises `ParserUnavailableError`.
7. **AC7 — Immutability:** `Frame` and the HTTP models cannot be mutated and survive a pickle round trip.
8. **AC8 — Response time:** `HttpTransaction.response_time_ms` is exact for a paired transaction and `None` when unanswered.
9. **AC9 — Indexed access:** lookups by frame number, protocol and stream use prebuilt indexes; stream 0 of TCP and of UDP are distinct.
10. **AC10 — Portable suite:** the full suite passes with tshark, and passes with PyShark cases skipped without it.
11. **AC11 — Protocol coverage:** every extractor in the documented schema (ip, tcp, udp, http, dns, tls) is exercised by at least one test on a real capture.

## Validation

| Gate | Command or procedure | Proves |
|---|---|---|
| Focused behavior | `python -m pytest -q tests/integration` | AC1–AC6, AC11 |
| Project gate | `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | AC1–AC11, plus no leaked tshark processes or event loops |
| Portability | `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | AC6, AC10 |
| Packaging | `pip install -e ".[dev]"` then `python -I -c "import sniffdash.parsing, sniffdash.repository"` | The package installs and imports cleanly |

## Risks and Decisions

| Decision or risk | Recommendation | Evidence / mitigation | Consequence if different |
|---|---|---|---|
| tshark reports URIs on responses, Scapy doesn't | Keep it; Phase 2 takes the URI from the request | Parity test compares request URIs only | Forcing equality would discard useful tshark data |
| `python-dotenv` is declared but unused in Phase 1 | Keep it; Phase 4 bootstrap loads `.env` | `.env.example` and README state this | Loading `.env` at import time would hide config side effects in library code |

## Agent Notes

Converted on 2026-11-05 from the original `docs/PRP_STEP_1.md` into the Wirasm/prp plan format, after the phase had been
implemented and merged (PR #1). The original ten acceptance criteria are preserved as AC1–AC10, with AC4 and AC7
sharpened to cover real dissectors and the HTTP models. AC11 was added by the post-merge audit; see the
implementation report's Review Dispositions.

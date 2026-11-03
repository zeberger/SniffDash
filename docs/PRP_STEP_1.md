# PRP — Step 1: Domain, Parsing & Repository Layers

## 1. Objective
Build the foundation layers of SniffDash. They turn a `.pcap` / `.pcapng` file into an immutable,
queryable collection of `Frame` objects. Every later step (metrics, HTTP pairing, LLM Q&A, UI)
reads its data from this foundation.

| Layer | Package | Responsibility |
|---|---|---|
| Domain | `sniffdash.domain` | Pure data models (`Frame`, `Endpoint`, `HttpRequest/Response/Transaction`), result containers, error hierarchy. No third-party imports. |
| Parsing | `sniffdash.parsing` | Detects the file format, checks file integrity, picks a backend (PyShark → Scapy fallback), extracts per-protocol fields, and produces a `ParseOutcome`. |
| Repository | `sniffdash.repository` | Indexed, read-only access to frames: by number, protocol, or stream, plus a Pandas view. |

Assignment requirements served: 23 (file ingestion), and the data foundation for 24–34. Frame numbers
match Wireshark exactly, because the evidence requirement (Req. 34) depends on that.

## 2. Inputs / Outputs
| Component | Input | Output |
|---|---|---|
| `detect_capture_format(path)` | file path | `CaptureFormat` or raises `UnsupportedFormatError` / `CorruptCaptureError` |
| `scan_integrity(path)` | file path | `IntegrityReport` (complete record count, truncated flag) |
| `ParserFactory.create(path, backend=None)` | path, optional backend | concrete `PacketParser` |
| `PacketParser.parse(path)` | path | `ParseOutcome(frames, issues, parser_name, partial)` |
| `InMemoryFrameRepository(frames)` | iterable of `Frame` | `FrameRepository` API + `to_dataframe()` |

Normalized layer schema (the contract between parsing and analysis), with keys inside `Frame.layers`:
`ip`, `tcp`, `udp`, `http`, `dns`, `tls`. Field names are documented in `parsing/extractors/base.py`.

## 3. Acceptance Criteria
1. `.pcap` (µs and ns variants) and `.pcapng` are detected by **magic bytes**, not by file extension.
2. Empty or garbage files raise typed exceptions. They never cause a raw traceback.
3. A truncated capture yields the frames that were readable, plus `partial=True` and an ERROR issue.
4. A packet that fails to decode adds a WARNING `ParseIssue`, and parsing continues.
5. PyShark and Scapy produce the same frame numbers, timestamps, endpoints and stream grouping for the same file.
6. If tshark is missing, AUTO mode falls back to Scapy. An explicit request for an unavailable backend raises `ParserUnavailableError`.
7. `Frame` and the HTTP models are immutable and picklable (needed for Streamlit caching).
8. `HttpTransaction.response_time_ms` is correct, and is `None` when no response exists.
9. Repository lookups by frame number, protocol and stream are O(1) index lookups.
10. All tests pass. PyShark tests are skipped automatically if tshark is not installed.

## 4. SOLID Verification Plan
| Principle | How Step 1 satisfies it |
|---|---|
| **S**ingle Responsibility | Format detection, integrity scan, extraction, frame assembly and storage each live in their own class or module. |
| **O**pen/Closed | New protocol = new file in `extractors/`. It is auto-discovered, so no existing file changes. New backend = `factory.register(...)`. |
| **L**iskov Substitution | `PySharkParser` and `ScapyParser` are interchangeable behind `PacketParser`. A cross-backend test proves it. |
| **I**nterface Segregation | `LayerExtractor` has 2 methods; `FrameRepository` exposes read-only queries only. |
| **D**ependency Inversion | Higher layers depend on `PacketParser` / `FrameRepository` abstractions. The domain layer imports nothing. |

## 5. Design Patterns Introduced
Factory (`ParserFactory`), Template Method (`PacketParser.parse`), Strategy + Registry (`LayerExtractor`),
Repository (`FrameRepository`), Notification (`ParseIssue`), Value Object (`Frame`, `Endpoint`).

## 6. Out of Scope (later steps)
Metrics and HTTP pairing (Step 2), LLM context and citation validation (Step 3), and the Streamlit UI (Step 4).

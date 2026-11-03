# SUMMARY — Step 1: Domain, Parsing & Repository

## Outcome
A capture file can now be turned into an immutable, indexed `FrameRepository`, through either backend,
with typed errors and partial-result recovery. All 10 acceptance criteria in `PRP_STEP_1.md` are met.

## Implemented
| Module | Key classes / functions | Pattern |
|---|---|---|
| `domain/models.py` | `Frame`, `Endpoint`, `FrozenMap`, `HttpRequest`, `HttpResponse`, `HttpTransaction`, `StatusClass` | Value Object |
| `domain/results.py` | `ParseOutcome`, `AnalysisResult`, `CaptureSummary`, `HttpAnalysisResult`, `AnalysisReport` | — |
| `domain/errors.py` | `SniffDashError` hierarchy, `ParseIssue`, `IssueSeverity` | Notification |
| `parsing/formats.py` | `detect_capture_format`, `scan_integrity` (pcap + pcapng walkers) | — |
| `parsing/base.py` | `PacketParser.parse()` | Template Method |
| `parsing/factory.py` | `ParserFactory` (priority + availability) | Factory |
| `parsing/pyshark_parser.py` | `PySharkParser` (two-pass tshark, private event loop) | Adapter |
| `parsing/scapy_parser.py` | `ScapyParser`, `StreamIndexer` | Adapter |
| `parsing/extractors/*` | ip, tcp/udp, http, dns, tls extractors (both backends), auto-discovered | Strategy + Registry |
| `parsing/assembler.py` | `FrameAssembler` (endpoints, stream, highest protocol) | — |
| `repository/*` | `FrameRepository` (ABC), `InMemoryFrameRepository` | Repository |

## Verification
| Run | Result |
|---|---|
| Full suite, tshark 4.6.9 present | **148 passed** |
| Same, `-X dev` + unraisable-exception warnings as errors | 148 passed, no resource leaks |
| Simulated machine without tshark | 129 passed, 19 skipped (PyShark-only tests) |
| `pip install -e ".[dev]"` + import | OK |

Coverage highlights: magic-byte variants, truncated pcap/pcapng, impossible record lengths,
per-packet and per-layer failure isolation, frame-number preservation after a skipped packet,
the max-packets limit, factory fallback rules, tshark `request_in`/`response_in` hints, pickling,
and **PyShark ↔ Scapy parity** on all fields that analysis uses.

## Issues found and fixed during the step
1. A request's `response_in` was empty → enabled tshark two-pass mode (`-2`).
2. pyshark's `__del__` re-closed the capture on a closed loop → idempotent `close()` subclass.
3. Backend difference: tshark annotates responses with their URI and Scapy does not. Documented; the parity test compares request URIs only.

## Known limitations (documented in code)
- Scapy fallback: no TCP reassembly and no TLS dissection.
- Only the first HTTP message of a segment holding several pipelined messages is extracted.
- PyShark throughput is about 1–3k packets/s; `ParserOptions.max_packets` bounds very large files.

## Next: Step 2
Metric calculators (Strategy), the HTTP analyzer with `CompositePairing` (tshark links → TCP FIFO),
`AnalysisEngine` + registry, and stream reconstruction for "Follow HTTP Stream".

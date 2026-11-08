# Implementation Report

**Plan:** `PRPs/plans/phase-2-analysis-engine.plan.md`
**Branch:** `feat/phase-2-analysis-engine`
**Status:** `COMPLETE`

## Outcome

`AnalysisEngine().run(repo)` now turns any parsed capture into an `AnalysisReport` containing:
- the capture summary: packets, bytes, start/end/duration, top-10 source and destination IPs, protocol distribution;
- a traffic timeline with an adaptive bucket size;
- every HTTP transaction: method, host, URI, endpoints, status, response time, request/response frame numbers, unanswered requests and orphan responses.

Any transaction can be rendered as Follow-HTTP-Stream text. Pairing is correct for pipelined traffic, port reuse,
retransmissions and multiple messages per segment, and both parsers produce the same transactions on every
reference capture. The output is pickle-safe and deterministic, ready for `st.cache_data` in Phase 4.

## Validation

| Command or check | Result | Evidence |
| --- | --- | --- |
| `python -m pytest -q tests/unit/test_plugins.py tests/unit/test_metrics.py tests/unit/test_http_pairing.py tests/unit/test_engine.py` | `passed` | 35 passed |
| `python -m pytest -q tests/integration/test_analysis_reference.py tests/integration/test_stream_bounds.py` | `passed` | 26 passed (both backends) |
| `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | `passed` | 214 passed (153 from Phase 1 + 61 new), no resource warnings |
| `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | `passed` | 180 passed, 34 skipped (PyShark-only cases) |
| Acceptance AC1–AC14 | `passed` | Each AC maps to the tests named in its plan task |

## Deviations and Decisions

- **Pairing uses FIFO per TCP stream only.** tshark's `request_in`/`response_in` links are kept in the parsed data but
  not used: a probe showed they mispair pipelined requests. This replaces the original architecture's
  "tshark links first" design.
- **Task 1's concurrency test** exercises `LazyDiscovery` (the shared component both registries now use) with a
  deliberately slow throwaway plugin package, instead of the extractor registry directly. Only a slow import can
  reliably reproduce the race window.
- **`SummaryAnalyzer` is not a registry plugin.** The engine runs it directly because a report requires a summary.
- **`numpy` is now a declared dependency.** It was previously only transitive through pandas; the timeline uses it directly.
- **Phase 1 parsing code changed** (planned Task 6): Scapy stream IDs now split on port reuse, and PyShark extracts all
  HTTP messages in a segment (`http.extra_messages`).

## Review Dispositions

Findings from the pre-implementation review (plan Risks and Decisions, probe-verified):

| ID | Disposition | Reason and evidence | Tracking |
| --- | --- | --- | --- |
| `R1` | `FIXED` | Plugin discovery set its flag before importing, so concurrent sessions could see a half-filled registry. Now uses a lock, and the flag is set after the imports (`tests/unit/test_plugins.py`). | `Not applicable` |
| `R2` | `FIXED` | Scapy merged a reused 4-tuple into one stream, so an unanswered old request could steal a new response. A new SYN now opens a new stream (`test_port_reuse_*`). | `Not applicable` |
| `R3` | `FIXED` | Scapy decoded a retransmitted request twice, which shifted later pairings. De-duplicated by (stream, sender, seq, position) (`test_retransmission_*`). | `Not applicable` |
| `R4` | `FIXED` | Only the first of several HTTP messages in one segment was extracted. PyShark now extracts all of them (`test_pyshark_pairs_two_responses_in_one_segment`). | `Not applicable` |
| `R5` | `DECLINED` | Scapy cannot split several HTTP messages in one segment. This is documented, and asserted by `test_scapy_two_responses_in_one_segment_is_a_documented_limitation`. | `Not applicable` |

## Completion Gate

- **Plan tasks complete:** `Yes`
- **Acceptance criteria satisfied:** `Yes`
- **Unresolved blocker:** `None`
- **Recovery:** `None`

## Intended Commit Scope

The `sniffdash.analysis` package (engine, registry, summary, timeline, HTTP messages/pairing/analyzer/stream), shared
`sniffdash.plugins` discovery, the `TrafficTimeline` and `HttpStreamView` result types, Phase 1 parsing hardening (Scapy
port reuse, PyShark multi-message segments), 4 new capture fixtures, 61 new tests, the Phase 2 plan and this report,
the PRD update, and `numpy` in `pyproject.toml`.

## Delivery

- **Commits:** `Not created`
- **Pull Request:** `Not opened`
- **Base / Head:** `main <- feat/phase-2-analysis-engine`
- **Source PRD:** `PRPs/prds/sniffdash.prd.md` — phase 2 marked `complete`
- **Tracked follow-ups:** `None`

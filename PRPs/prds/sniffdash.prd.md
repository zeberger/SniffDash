# SniffDash — Network Traffic Analysis Dashboard

## Problem Statement

Computer Networks students analyzing a `.pcap`/`.pcapng` capture have to reconstruct statistics, HTTP
request/response pairs and latencies by hand in Wireshark. That is slow, error-prone, and gives no way to
ask questions about a capture in plain language. If this isn't solved, course assignments 1–3 (Reqs 23–34)
cannot be met, and answers about a capture stay unverifiable because nothing links them to specific frames.

## Evidence

- Course specification, Assignments 1–3, Reqs 23–34: file ingestion, global metrics, HTTP transaction
  pairing with response times, "Follow HTTP Stream" view, and natural-language Q&A that cites frame
  numbers and timestamps.
- The user stated the system is the baseline for all three assignments, so later assignments will extend it
  (e.g. DNS or TLS analyzers) rather than replace it.
- Assumption: graders run the project on machines that may lack Wireshark. Needs validation through the
  course staff.

## Proposed Solution

A layered Python application: an immutable domain model, a parsing layer (PyShark/tshark primary, Scapy
fallback) behind a factory, a read-only frame repository, pluggable analyzers, an OpenAI-backed Q&A layer
that answers from a token-budgeted JSON context plus deterministic query tools, and a Streamlit UI behind a
single facade. A layered design was chosen over a single Streamlit script because the user requires SOLID
design and the code must absorb two more assignments without modifying its core.

## Key Hypothesis

We believe a layered, plugin-based PCAP dashboard with frame-cited AI answers will let students and graders
verify every course requirement (Reqs 23–34) directly from a capture file.
We'll know we're right when each of Reqs 23–34 is demonstrated by a passing automated test or a documented
manual check, and every frame the AI cites is verified to exist in the capture.

## What We're NOT Building

- Live packet capture (sniffing an interface) — the course specifies analysis of existing capture files.
- HTTP/2, HTTP/3 or TLS decryption — the requirements cover cleartext HTTP/1.x.
- Multi-user deployment, authentication or persistence of uploaded captures — single-user academic tool.
- A separate FastAPI backend — deferred; the facade keeps that option open without building it now.

## Success Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Requirement coverage | 12 of 12 (Reqs 23–34) | Requirement → test/check matrix in each phase report |
| Citation validity | 100% of frames cited in AI answers exist in the capture | `CitationValidator` checks every answer (Phase 3) |
| Test suite | 100% passing on every merged PR, with or without tshark | `python -m pytest -q` in each implementation report |
| Parse time for course sample captures | TBD | Measure on the course's sample captures once available |

## Open Questions

- [ ] Do grading machines have Wireshark (tshark) installed? Decides whether the Scapy fallback is the graded path.
- [ ] How large are the course's sample captures? Decides whether `ParserOptions.max_packets` needs a UI default.
- [ ] Do Assignments 2–3 add protocols (DNS/TLS analyzers) or new views? Decides whether to plan them as new PRD phases.

---

## Users & Context

**Primary User**
- **Who**: A Computer Networks student (and the grader reviewing their submission).
- **Current behavior**: Opens the capture in Wireshark, filters by hand, and copies values into a report.
- **Trigger**: An assignment requires statistics, HTTP latency analysis or answers about a capture.
- **Success state**: Upload the file and immediately see metrics, a paired HTTP table and stream details, then ask
  questions and get answers that cite frame numbers that can be checked in Wireshark.

**Job to Be Done**
When I am given a capture file for an assignment, I want to see its traffic structure and ask questions about it,
so I can answer accurately and prove each answer with specific frames.

**Non-Users**
Network operators monitoring production traffic, since this is not a real-time or high-volume tool, and anyone
needing encrypted-traffic inspection.

---

## Solution Detail

### Core Capabilities (MoSCoW)

| Priority | Capability | Rationale |
|----------|------------|-----------|
| Must | Upload/select `.pcap`/`.pcapng` with robust error handling (Req 23) | Entry point for everything else |
| Must | Packet count, start/end/duration, top IPs, protocol distribution (Reqs 24–25) | Module 1 requirements |
| Must | Traffic-over-time and protocol charts with Plotly (Req 26) | Module 1 requirement |
| Must | HTTP request↔response pairing with response time and frame numbers (Reqs 27–28) | Module 2 requirements |
| Must | "Follow HTTP Stream" detail view (Req 29) | Module 2 requirement |
| Must | LLM context extraction within token limits (Req 30) | Module 3 requirement |
| Must | Natural-language Q&A for slowest request, host counts, status codes, stream explanation (Reqs 31–33) | Module 3 requirements |
| Must | Answers cite frame numbers and timestamps, validated against the capture (Req 34) | Module 3 requirement |
| Should | Scapy fallback when tshark is missing | Grader machines may lack Wireshark |
| Should | Parse caching across Streamlit reruns | User-confirmed requirement; avoids re-parsing on every click |
| Should | Skill-level-adapted AI explanations | Personalized feature: the same facts, explained for beginner or expert |
| Should | HTTPS metadata analysis (sizes, timing, bursts → traffic-type inference) | Creativity feature: insight into encrypted traffic without decryption |
| Could | DNS / TLS analyzers | Extension points exist; likely future-assignment work |
| Won't | Live capture, HTTP/2–3, TLS decryption | See "What We're NOT Building" |

### MVP Scope

Phases 1–4 below. Together they cover Reqs 23–34, which is the minimum to test the hypothesis.

### User Flow

Upload capture → overview metrics and charts → HTTP transactions table → click a transaction to see its stream →
ask a question → answer with clickable frame evidence.

---

## Technical Approach

**Feasibility**: HIGH

**Architecture Notes**
- Layered: `domain ← parsing / repository ← analysis / llm ← application (AnalysisSession facade) ← ui`. Only `ui` imports Streamlit.
- Parsing: PyShark (tshark dissectors, TCP reassembly, Wireshark-identical frame numbers) with an automatic Scapy fallback, chosen by `ParserFactory`.
- Extensibility: auto-discovered registries for extractors (Phase 1), analyzers and result views (Phases 2 and 4), so new protocols need no core edits.
- LLM: OpenAI `gpt-4o-mini` / `gpt-4o` behind an `LLMClient` adapter. A compact JSON context plus function-calling tools give exact answers, and structured output plus a `CitationValidator` gives evidence.
- Caching: `st.cache_resource` / `st.cache_data` keyed by file hash.

**Technical Risks**

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| tshark missing on grader machine | M | Scapy fallback; the test suite skips PyShark-only tests (verified in Phase 1) |
| PyShark slow on large captures | M | `ParserOptions.max_packets`; parse once and cache |
| LLM cites non-existent frames | M | Deterministic tools + `CitationValidator` flags invalid citations |
| OpenAI rate limits / outages | L | Typed `LLMRateLimitError`, retry with backoff, clear UI message |
| Context overflow on large captures | M | Token-budgeted `ContextBuilder`; drill-down through tools instead of dumping frames |

---

## Implementation Phases

<!--
  STATUS: pending | in-progress | complete
  PARALLEL: phases that can run concurrently (e.g., "with 3" or "-")
  DEPENDS: phases that must complete first (e.g., "1, 2" or "-")
  PLAN: link to generated plan file once created
  REPORT: link to the implementation report once implemented
  PR: link to the pull request once opened
-->

| # | Phase | Description | Status | Parallel | Depends | Plan | Report | PR |
|---|-------|-------------|--------|----------|---------|------|--------|----|
| 1 | Foundation | Domain models, parsing (PyShark + Scapy), frame repository | complete | - | - | [plan](../plans/phase-1-foundation.plan.md) | [report](../reports/phase-1-foundation-report.md) | [#1](https://github.com/zeberger/SniffDash/pull/1) |
| 2 | Analysis engine | Metrics, HTTP pairing, stream reconstruction, analyzer registry | complete | - | 1 | [plan](../plans/phase-2-analysis-engine.plan.md) | [report](../reports/phase-2-analysis-engine-report.md) | [#3](https://github.com/zeberger/SniffDash/pull/3) |
| 3 | AI Q&A | Gemini client, context builder, query tools, skill-aware prompt, citation validation, HTTPS metadata analysis | complete | - | 2 | [plan](../plans/phase-3-ai-qa.plan.md) | [report](../reports/phase-3-ai-qa-report.md) | [#4](https://github.com/zeberger/SniffDash/pull/4) |
| 4 | Dashboard UI | AnalysisSession facade, caching, Streamlit views and chat | complete | - | 2, 3 | [plan](../plans/phase-4-dashboard.plan.md) | [report](../reports/phase-4-dashboard-report.md) | - |

### Phase Details

**Phase 1: Foundation**
- **Goal**: Turn any pcap/pcapng file into an immutable, indexed set of frames with Wireshark-identical numbering.
- **Scope**: `domain/`, `parsing/` (format detection, integrity scan, factory, both backends, extractors), `repository/`, tests.
- **Success signal**: Both backends produce identical analysis-relevant frames for the reference capture; corrupt input yields typed errors or partial results, never a crash.

**Phase 2: Analysis engine**
- **Goal**: Compute every Module 1 metric and Module 2 HTTP transaction from the repository (Reqs 24–28 data, Req 29 stream data).
- **Scope**: `analysis/` summary and timeline analyzers, `HttpAnalyzer` with FIFO pairing per TCP stream (RFC 9112 ordering), stream reconstruction, `AnalysisEngine` + registry with per-analyzer fault isolation.
- **Success signal**: The reference capture yields the known transactions (200 at 120 ms, 404 at 60 ms, one unanswered POST) and the known metrics.

**Phase 3: AI Q&A**
- **Goal**: Answer the four required question types with cited, validated frame evidence (Reqs 30–34).
- **Scope**: `llm/` context builder + token budget, query tools, Gemini adapter with retry, versioned skill-aware system prompt, `submit_answer` structured answers, `CitationValidator`, `.env` settings; `EncryptedFlowAnalyzer` plugin for HTTPS metadata.
- **Success signal**: With a mocked LLM, every required query type resolves through tools, and invalid citations are flagged; one live smoke test passes with a real key.

**Phase 4: Dashboard UI**
- **Goal**: Make Phases 1–3 usable in a browser (Reqs 23, 26, 29, 31).
- **Scope**: `application/` facade + bootstrap + `.env` config loading, `ui/` component registry, upload, overview, charts, HTTP table, stream inspector, chat, Streamlit caching (`@st.cache_data` on a single `load_and_analyze(file_bytes)` so parsing and analysis run once per file; the repository in `@st.cache_resource`).
- **Success signal**: The manual walkthrough of the User Flow works on the reference capture without re-parsing on reruns.

### Parallelism Notes

The phases run sequentially. Each consumes the previous phase's contracts: the analysis engine reads the repository, the
LLM layer reads the analysis report, and the UI renders all of them. Within Phase 4, the non-chat views could start
once Phase 2 is merged, but they are kept in one phase so the facade is designed once.

---

## Decisions Log

| Decision | Choice | Alternatives | Rationale |
|----------|--------|--------------|-----------|
| UI framework | Streamlit behind `AnalysisSession` facade | Dash; FastAPI + separate UI | Least overhead for a single-user tool; the facade keeps an API split possible (user-confirmed) |
| Parser | PyShark primary, Scapy fallback | Scapy only; raw `tshark -T ek` | Wireshark-identical numbering and dissection, with no hard Wireshark dependency (user-confirmed) |
| LLM access | Google Gemini (`google-genai`) behind `LLMClient` as `GeminiClient`; key `GEMINI_API_KEY` in `.env` | OpenAI SDK (original choice); LiteLLM; LangChain | Switched by the user (2026-11-09): free AI Studio key. The adapter design made it a one-class change |
| Structured answers on Gemini | Final answer as a `submit_answer` function call, function-calling mode `ANY` | `response_schema` together with tools | Google docs: tools + structured output only on Gemini 3 preview models |
| Personalization | Skill levels (beginner / intermediate / expert) change explanation style only | One fixed style | User feature request; the evidence rules stay identical across levels |
| Python | 3.11+ (developed on 3.14) | 3.10 | `StrEnum`, slots dataclasses (user-confirmed) |
| HTTP pairing | FIFO per TCP stream (stream ID first) | tshark `request_in`/`response_in` links first, FIFO fallback | Probe: tshark links mispair pipelined requests; FIFO is HTTP/1.1's guaranteed order and identical on both parsers |
| PRP artifact location | In-repo `PRPs/{prds,plans,reports}/` | `~/.prp/<project-key>/` store (PRP default) | Artifacts are course deliverables and must be versioned and reviewable in PRs |
| Delivery | One feature branch + PR per phase; user approves each git action | Direct pushes to `main` | User requirement |

---

## Research Summary

**Market Context**
Wireshark (including tshark) is the standard for manual capture analysis. It exposes the request↔response links
(`http.request_in` / `http.response_in`) and per-protocol fields SniffDash builds on, but offers no natural-language
querying with verifiable citations, which is the gap Module 3 targets.

**Technical Context**
Verified in Phase 1: tshark 4.6.9 provides HTTP pairing hints only in two-pass mode (`-2`); pyshark needs a private
event loop under Streamlit-style threads and an idempotent close; Scapy lacks TCP reassembly and TLS dissection but
matches tshark on frame numbers, timestamps, endpoints and stream grouping for the reference capture.

---

*Generated: 2026-11-05*
*Status: DRAFT - needs validation*

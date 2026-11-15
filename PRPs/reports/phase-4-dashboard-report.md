# Implementation Report

**Plan:** `PRPs/plans/phase-4-dashboard.plan.md`
**Branch:** `feat/phase-4-dashboard`
**Status:** `COMPLETE WITH DEFERRAL` — AC1–AC17 satisfied; AC18 (proven version range) deferred by the user, tracked as F1

## Outcome

`streamlit run app.py` opens the SniffDash dashboard. Users can:
- **load** a capture: upload it or pick it from `captures/`, choose the parser, and set the packet limit;
- see the **Overview**: headline metrics, traffic over time, protocol breakdown, top talkers, each with a table view;
- browse the **HTTP** transactions table with every Req 28 column, and click a row to get the "Follow HTTP Stream" inspector;
- see **Encrypted** flows with an inferred traffic type and the reasons;
- **Ask AI** at a chosen skill level, with every citation verified and linked to its stream;
- check **Issues** for parser and analyzer warnings.

Robustness:
- A capture is parsed **once**; reruns hit the cache.
- Failures are contained per tab, and while loading.
- Truncated captures are flagged on every tab **and to the AI**.

New users get `requirements.txt`, a demo-capture command, and a quick start.

## Validation

| Command or check | Result | Evidence |
| --- | --- | --- |
| `python -m pytest -q tests/unit/test_session.py tests/unit/test_charts.py tests/unit/test_layering.py tests/unit/test_setup.py tests/ui` | `passed` | 36 passed (facade 12, charts 8, layering 2, setup 2, AppTest UI 12) |
| `python -X dev -W error::ResourceWarning -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | `passed` | 360 passed, 5 skipped (live, opt-in) |
| `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | `passed` | 317 passed, 48 skipped |
| `python -m sniffdash.demo captures` | `passed` | Writes `demo_http.pcap`, `demo_https.pcap` (git-ignored) |
| `streamlit run app.py` (headless, port 8599) | `passed` | `/_stcore/health` = `ok`; main page HTTP 200; server stopped |
| Visual walkthrough of the User Flow (charts, row click, a live question) | `passed` | First walkthrough (2026-11-13) raised W1–W5 → Revision R1 below; the user re-checked the dashboard after R1 (2026-11-15) |

### Revision R1 (walkthrough feedback) — validation

| Command or check | Result | Evidence |
| --- | --- | --- |
| `python -m pytest -q tests/unit/test_charts.py tests/unit/test_labels.py tests/unit/test_session.py tests/ui` | `passed` | 51 passed |
| `python -m pytest -q tests/unit tests/ui` | `passed` | 308 passed |
| `python -X dev -m pytest -q -W error::pytest.PytestUnraisableExceptionWarning` | `passed` | 391 passed, 5 skipped (live, opt-in) |
| `$env:TSHARK_PATH="C:\nonexistent\tshark.exe"; python -m pytest -q` | `passed` | 348 passed, 48 skipped |
| `python -m pytest -q -m live_llm tests/integration/test_llm_reference.py` | `passed` | 5 passed in 76.9 s (real Gemini) |
| Live timing, demo capture, "Which HTTP request was the slowest?" | `passed` | Baseline 19.9 s / 3 requests → 5.5 s / 1 request (main model), 2.2 s / 1 request (lite); 2 valid citations each |
| Live timing, "Which status codes were returned?" | `passed` | 7.6 s / 1 request, 4 valid citations (main); 2.0 s / 2 requests (lite) |
| `python scripts/version_matrix.py --resolution lowest` | `failed` → deferred | 25 failed, 366 passed on Python 3.11 + declared minimums; see F1 |
| User's visual check of charts and tables | `passed` | 2026-11-15 |

## Deviations and Decisions

- **Self-audit A1–A10** (requested by the user before coding) was built into the design. It added AC11–AC12, a
  `partial` flag on `AnalysisReport`, and a **new prompt version `system_v2`** (adds the partial-capture rule; `system_v1`
  is kept as history).
- **Test-fixture module naming:** a `tests/ui/conftest.py` shadowed `tests/conftest.py` (both import as `conftest`)
  and broke 4 test modules in a full run. The fixtures moved to `tests/ui/ui_fixtures.py` (imported explicitly), and
  the LLM doubles moved to `tests/llm_doubles.py`. The old file was deleted with the user's two approvals.
- **Charts:** single-series designs from the dataviz guidance (one hue, one axis, table view). The protocol chart is a
  sorted horizontal bar (allowed by the spec instead of a pie).
- **Known harmless warning:** Streamlit's `AppTest` leaves a temporary directory that Python cleans up at interpreter
  shutdown (a `ResourceWarning` after the tests finish; none of our code uses `TemporaryDirectory`).

**Revision R1 (2026-11-13 → 15):**
- **Zoom (user decisions):** the plan first said "no zoom". The user asked for bounded panning, then for drag = pan.
  Implemented with Plotly `minallowed`/`maxallowed` on the time axis and `dragmode="pan"`; the bar charts are fixed.
- **Clipped labels (user report):** the cause was the fixed 8 px chart margins (`charts.py`, Phase 4), which cut "TCP"
  down to "P". Every axis now uses `automargin`.
- **Timeline counts, not rates:** on short captures the per-second rate was misleading (2 packets in 10 ms showed as
  "200 packets/s"), so the chart plots counts per interval and names the interval width.
- **Fallback on overload (beyond the plan):** live runs returned intermittent `504 DEADLINE_EXCEEDED` from the main
  model even after retries, while the lite model answered. The fallback switch therefore also covers server errors
  that outlast the retries, not only 429. Tested in `test_overloaded_main_model_switches_to_the_fallback`.
- **Prompt rule 2 tightened (`system_v2.md`):** the model still made a lookup when the context already held the answer.
  It now calls `submit_answer` directly when the context has every fact and citation; status-code counts were left
  out of the examples, because they carry no frame numbers to cite. Live: the "slowest" question went from 2 requests to 1.
- **Bug found by the new tests:** in `views/http.py` a local variable named `labels` shadowed the new `labels` module
  (`UnboundLocalError`). Renamed to `captions`.
- **`uv` is not in `requirements.txt`:** it is a developer tool for the version check, installed with `pip install uv`
  (the script says so if it's missing), so graders don't install it needlessly.
- **R1.4 deferred by the user** after the first matrix run (see F1).

## Review Dispositions

| ID | Disposition | Reason and evidence | Tracking |
| --- | --- | --- | --- |
| `A1` | `FIXED` | Truncation was invisible to the AI: `AnalysisReport.partial`, `capture.partial` in context, prompt v2 rule, banner (`test_partial_capture_is_announced_to_the_model`, `test_packet_limit_shows_partial_banner`) | `Not applicable` |
| `A2` | `FIXED` | Chat key = bytes + parser + limit (`test_fingerprint_covers_bytes_parser_and_limit`) | `Not applicable` |
| `A3` | `FIXED` | Load-level error boundary; failed loads not cached (`test_broken_file_shows_a_friendly_error`, `test_failed_load_is_not_cached`) | `Not applicable` |
| `A4` | `FIXED` | UTC and Wireshark-style relative seconds in tables (`test_transactions_table_has_every_required_column`) | `Not applicable` |
| `A5` | `FIXED` | `.streamlit/config.toml`: usage stats off, 500 MB uploads | `Not applicable` |
| `A6` | `FIXED` | Empty states; Encrypted tab only when flows exist (`test_overview_of_the_http_demo`, chart empty-state tests) | `Not applicable` |
| `A7` | `FIXED` | Failed questions stored as failed; history kept (`test_failed_question_keeps_history`) | `Not applicable` |
| `A8` | `FIXED` | Caches cleared around every UI test (`ui_fixtures.app`) | `Not applicable` |
| `A9` | `FIXED` | Capture cache `max_entries=2` | `Not applicable` |
| `A10` | `FIXED` | Non-HTTP evidence shows frame metadata (`test_stream_and_lookups`) | `Not applicable` |
| `W1` | `FIXED` | Cryptic chart labels: descriptive axis titles, interval width named (`test_every_axis_has_a_descriptive_title`, `test_traffic_over_time_counts_per_interval`); no clipping (`test_labels_get_their_own_space`, `test_bar_values_have_headroom`) | `Not applicable` |
| `W2` | `FIXED` | Zoom beyond the data: bounded zoom/pan, drag pans, bars fixed (`test_time_axis_is_bounded_to_the_capture`, `test_bar_charts_do_not_move`) | `Not applicable` |
| `W3` | `FIXED` | Ambiguous table headers: `ui/labels.py`, every facade column labelled and explained (`test_labels.py`, 8 tables) | `Not applicable` |
| `W4` | `TRACKED FOLLOW-UP` | Version range unproven; first matrix run found wrong minimums. Deferred by the user | `F1` |
| `W5` | `FIXED` | Slow AI / few questions: thinking "low", `resp_time` in context, prompt rule, answer reuse, fallback model (`test_gemini_client.py`, `test_service.py`, `test_context.py`, `test_repeated_question_reuses_the_answer`; live 5/5) | `Not applicable` |

## Tracked Follow-ups

- **F1 — Prove the version range (AC18, plan R1.4).** Deferred by the user on 2026-11-13. Measured so far: real
  minimums are `numpy>=2.0`, `pandas>=2.2.3`, `google-genai>=1.51`; Streamlit, Scapy and Plotly are not yet measured.
  The exact pause state, how to undo the testing side effects (about 1.3 GB under `.matrix\` and `%LOCALAPPDATA%\uv` /
  `%APPDATA%\uv`), and how to resume are in the plan, section "R1.4 status".

## Completion Gate

- **Plan tasks complete:** `Yes`, except R1.4 (deferred by the user; F1)
- **Acceptance criteria satisfied:** `Yes` for AC1–AC17; AC18 open (F1). The user checked the dashboard visually after R1.
- **Unresolved blocker:** `None`
- **Recovery:** `None`

## Intended Commit Scope

`sniffdash.application` (facade, bootstrap), `sniffdash.ui` (app, cache, registry, charts, five views),
`sniffdash.demo` (builders moved from tests + CLI), `app.py`, `.streamlit/config.toml`, `requirements.txt`,
dependency updates, `AnalysisReport.partial` + prompt `system_v2` + context flag, test reorganization (`llm_doubles.py`,
`ui/ui_fixtures.py`, `ui/ui_helpers.py`), 37 new tests (360 total, up from 323), README, and the Phase 4 plan and report with the PRD update.

## Delivery

- **Commits:** `cee378d feat(phase-4): Streamlit dashboard with cached loading and verified AI chat`;
  `ec4439b fix(phase-4): readable charts and tables, faster Ask AI (walkthrough R1)`; this report update
- **Pull Request:** `Not opened` (PR #5; link recorded after it exists)
- **Base / Head:** `main <- feat/phase-4-dashboard`
- **Source PRD:** `PRPs/prds/sniffdash.prd.md` — phase 4 marked `complete`
- **Tracked follow-ups:** `F1` (version range, deferred by the user)

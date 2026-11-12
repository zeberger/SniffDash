# Implementation Report

**Plan:** `PRPs/plans/phase-4-dashboard.plan.md`
**Branch:** `feat/phase-4-dashboard`
**Status:** `COMPLETE` (pending the user's visual walkthrough, below)

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
| Visual walkthrough of the User Flow (charts, row click, a live question) | `pending` | Needs the user's eyes; see the summary for the steps |

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

## Completion Gate

- **Plan tasks complete:** `Yes`
- **Acceptance criteria satisfied:** `Yes` — AC1–AC12 automated. The success signal's visual part is pending the user's walkthrough.
- **Unresolved blocker:** `None`
- **Recovery:** `None`

## Intended Commit Scope

`sniffdash.application` (facade, bootstrap), `sniffdash.ui` (app, cache, registry, charts, five views),
`sniffdash.demo` (builders moved from tests + CLI), `app.py`, `.streamlit/config.toml`, `requirements.txt`,
dependency updates, `AnalysisReport.partial` + prompt `system_v2` + context flag, test reorganization (`llm_doubles.py`,
`ui/ui_fixtures.py`, `ui/ui_helpers.py`), 37 new tests (360 total, up from 323), README, and the Phase 4 plan and report with the PRD update.

## Delivery

- **Commits:** `ef8be05 docs(prp): record delivery links for PR #4`; Phase 4: `Not created`
- **Pull Request:** `Not opened`
- **Base / Head:** `main <- feat/phase-4-dashboard`
- **Source PRD:** `PRPs/prds/sniffdash.prd.md` — phase 4 marked `complete`
- **Tracked follow-ups:** `None`

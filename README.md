# SniffDash — Network Traffic Analysis Dashboard

Analyzes `.pcap` / `.pcapng` captures: global statistics, HTTP transaction reconstruction,
and an AI Q&A interface whose answers cite frame-level evidence.

**Status:** Phases 1–3 of 4 are complete (parsing foundation; analysis engine; AI Q&A with verified
frame-level evidence, skill levels, and HTTPS traffic-shape analysis). Phase 4 (dashboard UI) is next.
Roadmap and phase status: [`PRPs/prds/sniffdash.prd.md`](PRPs/prds/sniffdash.prd.md).

## Setup

```powershell
# 1. Python 3.11+ virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # bash: source .venv/Scripts/activate
pip install -e ".[dev]"

# 2. Wireshark (recommended): provides tshark for the primary PyShark parser.
#    https://www.wireshark.org/download.html. If tshark is not on PATH, it is
#    found automatically in the default install folder; otherwise set the
#    TSHARK_PATH environment variable. Without Wireshark, SniffDash falls back
#    to the pure-Python Scapy parser.

# 3. AI key (free): https://aistudio.google.com/apikey
copy .env.example .env                # then set GEMINI_API_KEY=... in .env
```

## AI Q&A (Gemini)

- **Key:** create a free key in Google AI Studio, restrict it to the Gemini (Generative Language) API,
  and put it in `.env` as `GEMINI_API_KEY`. `GEMINI_MODEL` selects the model (default `gemini-3.5-flash`; Gemini 2.5 is closed to new users).
- **Skill levels:** `beginner`, `intermediate` (default), `expert` change how answers are *explained*;
  the facts and the evidence rules are identical at every level.
- **Evidence:** every answer lists frame numbers and timestamps, and each one is checked against
  the capture; citations that don't match are flagged instead of shown as fact.
- **What is sent to Google:** a JSON summary of the capture (statistics, hosts, URIs, timings) and, when
  the model asks for one, a transaction's text, with `Authorization`/`Cookie` headers and password-like
  fields redacted and bodies truncated. On the free tier, Google may use prompts to improve its products.
- **Quota:** free-tier limits are small; one question uses about 1–5 requests.

## Tests

```powershell
python -m pytest -q                   # offline; PyShark tests auto-skip if tshark is missing
python -m pytest -q -m live_llm       # optional: real Gemini calls (needs GEMINI_API_KEY; uses quota)
```

## Project layout

```
src/sniffdash/
  domain/        models, results, errors (no third-party imports)
  parsing/       format detection, ParserFactory, PyShark/Scapy parsers, extractors/
  repository/    FrameRepository interface + in-memory implementation
  analysis/      AnalysisEngine + analyzer plugins: summary, timeline, HTTP pairing, stream view,
                 encrypted-flow (HTTPS) metadata
  llm/           Gemini adapter, context builder, query tools, prompts, citation validation
  config.py      settings from environment / .env
tests/
  unit/          isolated logic tests
  integration/   real parsers on generated captures, backend parity
PRPs/            PRP artifacts (Wirasm/prp format)
  prds/          sniffdash.prd.md: problem, scope, phases table (status, plan, report, PR links)
  plans/         phase-N-*.plan.md: written BEFORE each phase is implemented
  reports/       phase-N-*-report.md: written AFTER, with validation evidence
```

## Workflow (per PRD phase)

1. **Plan:** `PRPs/plans/phase-N-*.plan.md`, reviewed before any code.
2. **Implement** on a feature branch; the full test suite must pass.
3. **Report:** `PRPs/reports/phase-N-*-report.md`, and update the phase row in the PRD.
4. **Pull request** into `main` on `https://github.com/zeberger/SniffDash`; merge after review.

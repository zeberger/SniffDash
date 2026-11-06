# SniffDash — Network Traffic Analysis Dashboard

Analyzes `.pcap` / `.pcapng` captures: global statistics, HTTP transaction reconstruction,
and an AI Q&A interface whose answers cite frame-level evidence.

**Status:** Phase 1 of 4 (domain, parsing and repository layers) is complete.
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

# 3. Secrets (read by the app from Phase 4 on)
copy .env.example .env                # then put your OpenAI key in .env
```

## Tests

```powershell
python -m pytest -q                   # PyShark tests auto-skip if tshark is missing
```

## Project layout

```
src/sniffdash/
  domain/        models, results, errors (no third-party imports)
  parsing/       format detection, ParserFactory, PyShark/Scapy parsers, extractors/
  repository/    FrameRepository interface + in-memory implementation
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

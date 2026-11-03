# SniffDash — Network Traffic Analysis Dashboard

Analyzes `.pcap` / `.pcapng` captures: global statistics, HTTP transaction reconstruction,
and an AI Q&A interface whose answers cite frame-level evidence.

**Status:** Step 1 of 4 (domain, parsing and repository layers) is complete. See `docs/`.

## Setup

```powershell
# 1. Python 3.11+ virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # bash: source .venv/Scripts/activate
pip install -e ".[dev]"

# 2. Wireshark (recommended): provides tshark for the primary PyShark parser.
#    https://www.wireshark.org/download.html. If tshark is not on PATH, it is
#    found automatically in the default install folder, or set TSHARK_PATH in .env.
#    Without Wireshark, SniffDash falls back to the pure-Python Scapy parser.

# 3. Secrets
copy .env.example .env                # then put your OpenAI key in .env (needed from Step 3)
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
docs/            PRP_STEP_X.md (before each step), SUMMARY_STEP_X.md (after)
```

## Git workflow

One commit per step (`feat(step-N): ...`), made only after the full test suite passes,
then pushed to `origin` (`https://github.com/zeberger/SnifDash.git`).

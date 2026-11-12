# SniffDash — Network Traffic Analysis Dashboard

Analyzes `.pcap` / `.pcapng` captures in the browser: global statistics and charts, HTTP transaction
reconstruction with a "Follow HTTP Stream" view, encrypted-traffic (HTTPS) characterization, and an AI Q&A
interface whose answers cite frame numbers and timestamps that are **verified against the capture**.

**Status:** all four phases are complete (parsing → analysis → AI Q&A → dashboard).
Roadmap and phase status: [`PRPs/prds/sniffdash.prd.md`](PRPs/prds/sniffdash.prd.md).

## Quick start

```powershell
# 1. Python 3.11+ virtual environment and dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # bash: source .venv/Scripts/activate
pip install -r requirements.txt         # or, for development:  pip install -e ".[dev]"

# 2. (Recommended) Wireshark: https://www.wireshark.org/download.html
#    Provides tshark for the primary PyShark parser. Found automatically in its default
#    install folder; without it, SniffDash falls back to the pure-Python Scapy parser.

# 3. (Optional) AI answers: a free key from https://aistudio.google.com/apikey
copy .env.example .env                 # then set GEMINI_API_KEY=... in .env

# 4. Demo captures and the dashboard
python -m sniffdash.demo captures       # writes captures/demo_http.pcap and demo_https.pcap
streamlit run app.py                    # opens http://localhost:8501
```

## Using the dashboard

| Where | What you get |
|---|---|
| **Sidebar** | Upload a capture, or pick one from `captures/`; choose the parser (auto / PyShark / Scapy); set **Max packets** (default 200,000). Larger files are cut there and clearly marked **partial**. |
| **Overview** | Packets, duration, data volume, start/end time; traffic over time (packets/s or bytes/s); protocol breakdown; top source / destination IPs. Every chart has a table view. |
| **HTTP** | Every transaction: method, host, URI, source/destination IP:port, status, response time, request/response frame numbers, absolute (UTC) and relative time. **Click a row** to see its request and response, as in Wireshark's *Follow HTTP Stream*. |
| **Encrypted** | (shown when the capture has HTTPS/TLS) Each encrypted connection's volume, timing and bursts, with an *inferred* traffic type (video streaming, download, API polling) and the reasons behind it. |
| **Ask AI** | Ask in plain language (English or Hebrew) at a **beginner / intermediate / expert** level. Each answer lists its evidence (frame + timestamp), checked against the capture; unverifiable citations are flagged. Chat history is kept per capture. |
| **Issues** | Everything the parser or analyzers reported: malformed packets, truncation, analyzer failures. |

## AI Q&A (Gemini)

- **Key:** create a free key in Google AI Studio and put it in `.env` as `GEMINI_API_KEY`. `GEMINI_MODEL`
  selects the model (default `gemini-3.5-flash`; Gemini 2.5 is closed to new users). Optionally restrict the key
  to the Generative Language API in the Google Cloud console.
- **Skill levels** change how answers are *explained*; the facts and the evidence rules are identical at every level.
- **What is sent to Google:** a JSON summary of the capture (statistics, hosts, URIs, timings) and, when the model
  asks for one, a transaction's text, with `Authorization` / `Cookie` headers and password-like fields redacted and
  bodies truncated. On the free tier, Google may use prompts to improve its products.
- **Quota:** free-tier limits are small; one question uses about 1–5 requests. Errors (quota, key) are shown in the
  chat and never erase earlier answers.
- **Privacy defaults:** `.env` is git-ignored; Streamlit's usage statistics are switched off in `.streamlit/config.toml`.

## Tests

```powershell
python -m pytest -q                     # offline: unit, integration and headless dashboard tests
python -m pytest -q -m live_llm         # optional: real Gemini calls (needs GEMINI_API_KEY; uses quota)
```

PyShark-specific tests skip automatically when Wireshark isn't installed.

## Project layout

```
app.py              streamlit entry point
src/sniffdash/
  domain/           models, results, errors (no third-party imports)
  parsing/          format detection, ParserFactory, PyShark/Scapy parsers, extractors/
  repository/       FrameRepository interface + in-memory implementation
  analysis/         AnalysisEngine + analyzer plugins: summary, timeline, HTTP pairing, stream view,
                    encrypted-flow (HTTPS) metadata
  llm/              Gemini adapter, context builder, query tools, prompts, citation validation
  application/      AnalysisSession facade (what the UI talks to) and service wiring
  ui/               Streamlit app: sidebar, cache, view registry, views/ (the only layer importing Streamlit)
  config.py         settings from environment / .env
  demo.py           synthetic demo captures (python -m sniffdash.demo)
tests/
  unit/             isolated logic tests
  integration/      real parsers on generated captures, backend parity, end-to-end Q&A
  ui/               headless dashboard tests (Streamlit AppTest)
PRPs/               PRP artifacts (Wirasm/prp format)
  prds/             sniffdash.prd.md: problem, scope, phases table (status, plan, report, PR links)
  plans/            phase-N-*.plan.md: written BEFORE each phase is implemented
  reports/          phase-N-*-report.md: written AFTER, with validation evidence
```

## Workflow (per PRD phase)

1. **Plan:** `PRPs/plans/phase-N-*.plan.md`, reviewed before any code.
2. **Implement** on a feature branch; the full test suite must pass.
3. **Report:** `PRPs/reports/phase-N-*-report.md`, and update the phase row in the PRD.
4. **Pull request** into `main` on `https://github.com/zeberger/SniffDash`; merge after review.

"""AnalysisSession: the Facade between the UI and everything below it.

The dashboard never touches parsers, repositories, analyzers or the LLM layer
directly. It calls ``load_capture`` once per file, then asks the session for
ready-to-render tables and actions. This keeps every UI-facing decision (column
names, units, time formats) in one plain-Python, unit-testable place, and keeps
the core free of Streamlit.

Times are shown two ways, like Wireshark: absolute UTC, and seconds relative to
the first frame (Wireshark's default "Time" column).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from sniffdash.analysis import AnalysisEngine
from sniffdash.analysis.analyzers.http import HttpStreamReconstructor
from sniffdash.domain.errors import CorruptCaptureError, IssueSeverity, ParseIssue
from sniffdash.domain.models import HttpTransaction
from sniffdash.domain.results import (
    AnalysisReport, CaptureSummary, EncryptedFlowsResult, HttpAnalysisResult, HttpStreamView, TrafficTimeline,
)
from sniffdash.llm.answer import SkillLevel, ValidatedAnswer
from sniffdash.parsing.extractors.base import Backend
from sniffdash.parsing.factory import ParserFactory
from sniffdash.parsing.options import ParserOptions
from sniffdash.repository import InMemoryFrameRepository
from sniffdash.repository.base import FrameRepository

DEFAULT_MAX_PACKETS = 200_000
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")


def capture_fingerprint(data: bytes, backend: Backend | None, max_packets: int | None) -> str:
    """Identity of one *analysis* of a file: same bytes parsed differently = different frames.

    Used to key chat history, so answers never refer to a different parse of the file.
    """
    digest = hashlib.sha256(data).hexdigest()[:16]
    return f"{digest}:{backend.value if backend else 'auto'}:{max_packets or 'all'}"


def load_capture(data: bytes, name: str, *, backend: Backend | None = None,
                 max_packets: int | None = DEFAULT_MAX_PACKETS,
                 factory: ParserFactory | None = None) -> AnalysisSession:
    """Parse + analyze uploaded bytes. Raises the typed ``CaptureError`` family on bad input."""
    if not data:
        raise CorruptCaptureError(f"'{name}' is empty.")
    suffix = Path(name).suffix.lower()
    fd, tmp_name = tempfile.mkstemp(prefix="sniffdash-", suffix=suffix if suffix in CAPTURE_SUFFIXES else ".pcap")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        parser = (factory or ParserFactory.default(ParserOptions(max_packets=max_packets))).create(tmp, backend)
        outcome = parser.parse(tmp)
    finally:
        tmp.unlink(missing_ok=True)  # the upload's temporary copy never outlives the parse

    repo = InMemoryFrameRepository.from_outcome(outcome)
    report = AnalysisEngine().run(repo, source=name, issues=outcome.issues, partial=outcome.partial)
    return AnalysisSession(name=name, fingerprint=capture_fingerprint(data, backend, max_packets),
                           parser_name=outcome.parser_name, report=report, repo=repo)


@dataclass(frozen=True)
class AnalysisSession:
    name: str
    fingerprint: str
    parser_name: str
    report: AnalysisReport
    repo: FrameRepository

    # --- convenience views on the report -------------------------------------------

    @property
    def summary(self) -> CaptureSummary:
        return self.report.summary

    @property
    def partial(self) -> bool:
        return self.report.partial

    @property
    def http(self) -> HttpAnalysisResult | None:
        return self.report.get(HttpAnalysisResult)

    @property
    def encrypted(self) -> EncryptedFlowsResult | None:
        return self.report.get(EncryptedFlowsResult)

    @property
    def issues(self) -> tuple[ParseIssue, ...]:
        return self.report.issues

    def has_errors(self) -> bool:
        return any(i.severity is IssueSeverity.ERROR for i in self.issues)

    def relative(self, ts: float | None) -> float | None:
        start = self.summary.start_ts
        return None if ts is None or start is None else round(ts - start, 6)

    # --- tables for the UI -------------------------------------------------------

    def timeline_frame(self) -> pd.DataFrame:
        timeline = self.report.get(TrafficTimeline)
        columns = ["time", "rel_s", "packets", "bytes", "packets_per_s", "bytes_per_s"]
        if timeline is None or not timeline.buckets:
            return pd.DataFrame(columns=columns)
        step = timeline.bucket_seconds
        rows = [(pd.Timestamp(ts, unit="s", tz="UTC"), self.relative(ts), p, b, p / step, b / step)
                for ts, p, b in timeline.buckets]
        return pd.DataFrame(rows, columns=columns)

    def protocol_frame(self) -> pd.DataFrame:
        rows = list(self.summary.protocol_distribution)
        df = pd.DataFrame(rows, columns=["protocol", "packets"])
        total = df["packets"].sum()
        df["share"] = df["packets"] / total if total else 0.0
        return df

    def talkers_frame(self, direction: str = "source") -> pd.DataFrame:
        rows = self.summary.top_sources if direction == "source" else self.summary.top_destinations
        return pd.DataFrame(list(rows), columns=["ip", "packets"])

    def transactions_frame(self) -> pd.DataFrame:
        """One row per HTTP transaction with every Req 28 column."""
        columns = ["id", "method", "host", "uri", "source", "destination", "status", "reason",
                   "response_ms", "request_frame", "response_frame", "time_utc", "rel_s"]
        if self.http is None:
            return pd.DataFrame(columns=columns)
        rows = []
        for tx in self.http.transactions:
            req, resp = tx.request, tx.response
            rows.append({
                "id": tx.id, "method": req.method, "host": req.effective_host, "uri": req.uri,
                "source": str(req.src), "destination": str(req.dst),
                "status": resp.status_code if resp else None, "reason": resp.reason if resp else "no response",
                "response_ms": round(tx.response_time_ms, 3) if resp else None,
                "request_frame": req.frame_number, "response_frame": resp.frame_number if resp else None,
                "time_utc": pd.Timestamp(req.timestamp, unit="s", tz="UTC"), "rel_s": self.relative(req.timestamp),
            })
        df = pd.DataFrame(rows, columns=columns)
        for col in ("status", "response_frame"):
            df[col] = df[col].astype("Int64")  # nullable: unanswered requests have none
        return df

    def encrypted_frame(self) -> pd.DataFrame:
        columns = ["stream", "client", "server", "sni", "inferred_type", "duration_s", "bytes_down",
                   "bytes_up", "bursts", "first_frame", "last_frame", "reasons"]
        if self.encrypted is None:
            return pd.DataFrame(columns=columns)
        rows = [{
            "stream": f.stream_id, "client": str(f.client), "server": str(f.server), "sni": f.sni,
            "inferred_type": f.label, "duration_s": round(f.duration_s, 3), "bytes_down": f.bytes_down,
            "bytes_up": f.bytes_up, "bursts": f.burst_count, "first_frame": f.first_frame,
            "last_frame": f.last_frame, "reasons": "; ".join(f.reasons),
        } for f in self.encrypted.flows]
        return pd.DataFrame(rows, columns=columns)

    def issues_frame(self) -> pd.DataFrame:
        return pd.DataFrame([{"severity": i.severity.value, "frame": i.frame_number, "message": i.message}
                             for i in self.issues], columns=["severity", "frame", "message"])

    # --- lookups and actions -----------------------------------------------------

    def transaction(self, tx_id: str) -> HttpTransaction | None:
        return next((tx for tx in (self.http.transactions if self.http else ()) if tx.id == tx_id), None)

    def transaction_for_frame(self, frame_number: int) -> HttpTransaction | None:
        return self.http.find_by_frame(frame_number) if self.http else None

    def stream(self, tx_id: str) -> HttpStreamView | None:
        tx = self.transaction(tx_id)
        return HttpStreamReconstructor().reconstruct(tx, self.repo) if tx else None

    def frame_info(self, frame_number: int) -> dict[str, Any] | None:
        """Metadata for evidence that cites a non-HTTP frame."""
        f = self.repo.get(frame_number)
        if f is None:
            return None
        return {"frame": f.number, "time_utc": pd.Timestamp(f.timestamp, unit="s", tz="UTC"),
                "rel_s": self.relative(f.timestamp), "length": f.length,
                "source": str(f.src) if f.src else None, "destination": str(f.dst) if f.dst else None,
                "protocols": ":".join(f.protocols)}

    def ask(self, question: str, level: SkillLevel | str, service: Any) -> ValidatedAnswer:
        return service.ask(question, self.report, self.repo, skill_level=level)

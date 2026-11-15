"""ContextBuilder: the capture, condensed into a token-budgeted JSON document (Req 30).

The model gets an *overview* up front and fetches *details* through tools, so the
prompt size stays roughly constant whether the capture has 13 frames or 1,000,000.

Sections, most important first: capture facts, protocols, top talkers, HTTP
overview (including the slowest transactions), the encrypted-flow overview, and
finally a compact transaction index. Only the index is ever truncated, and the
truncation is announced so the model knows to use tools for the rest. No headers
or bodies are included here; those come only through the (redacting) tools.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sniffdash.domain.results import AnalysisReport, EncryptedFlowsResult, HttpAnalysisResult
from sniffdash.domain.models import HttpTransaction
from sniffdash.llm.answer import format_ts

CHARS_PER_TOKEN = 3  # conservative for JSON (real ratio ≈ 3–4): over-estimates, never under-


def estimate_tokens(text: str) -> int:
    return -(-len(text) // CHARS_PER_TOKEN)  # ceiling division


def _ms(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


def index_row(tx: HttpTransaction) -> list[Any]:
    """[id, req_frame, resp_frame, req_time, resp_time, method, host, uri, status, rt_ms].

    Both frames carry their timestamps, so a question answerable from the overview can
    cite request AND response without a lookup (one Gemini request instead of three).
    """
    resp = tx.response
    return [tx.id, tx.request.frame_number, resp.frame_number if resp else None,
            format_ts(tx.request.timestamp), format_ts(resp.timestamp) if resp else None,
            tx.request.method, tx.request.effective_host, tx.request.uri, tx.status_code, _ms(tx.response_time_ms)]


INDEX_COLUMNS = ["id", "req_frame", "resp_frame", "req_time", "resp_time", "method", "host", "uri", "status", "rt_ms"]


class ContextBuilder:
    def __init__(self, budget_tokens: int = 6000, slowest_shown: int = 5) -> None:
        self._budget = budget_tokens
        self._slowest = slowest_shown

    def build(self, report: AnalysisReport) -> dict[str, Any]:
        context = self._fixed_sections(report)
        http = report.get(HttpAnalysisResult)
        rows = [index_row(tx) for tx in (http.transactions if http else ())]

        total = len(rows)
        context["transaction_index"] = {"columns": INDEX_COLUMNS, "rows": rows}
        while rows and estimate_tokens(self.render(context)) > self._budget:
            # Drop ~25% of the remaining rows from the end per round; the "slowest"
            # section above already preserves the most important transactions.
            rows = rows[: max(0, len(rows) - max(1, len(rows) // 4))]
            context["transaction_index"] = {
                "columns": INDEX_COLUMNS, "rows": rows,
                "truncated": {"omitted": total - len(rows),
                              "hint": "Use the tools to look up transactions not listed here."},
            }
        return context

    @staticmethod
    def render(context: dict[str, Any]) -> str:
        return json.dumps(context, ensure_ascii=False, separators=(",", ":"), sort_keys=False)

    def _fixed_sections(self, report: AnalysisReport) -> dict[str, Any]:
        s = report.summary
        context: dict[str, Any] = {
            "capture": {
                "file": report.source, "packets": s.packet_count, "bytes": s.total_bytes,
                "start": format_ts(s.start_ts) if s.start_ts is not None else None,
                "end": format_ts(s.end_ts) if s.end_ts is not None else None,
                "duration_s": round(s.duration_s, 6),
                "partial": report.partial,
            },
            "protocols": dict(s.protocol_distribution),
            "top_sources": dict(s.top_sources),
            "top_destinations": dict(s.top_destinations),
        }
        if report.partial:
            context["capture"]["partial_note"] = (
                "Only part of the file was analyzed (truncated file or packet limit). "
                "All counts describe the loaded portion only.")

        http = report.get(HttpAnalysisResult)
        if http is not None:
            answered = [tx for tx in http.transactions if tx.is_complete]
            slowest = sorted(answered, key=lambda tx: -tx.response_time_ms)[: self._slowest]
            context["http_overview"] = {
                "transactions": len(http.transactions),
                "answered": len(answered),
                "unanswered": len(http.transactions) - len(answered),
                "orphan_responses": len(http.orphan_responses),
                "by_status": {str(k): v for k, v in sorted(
                    Counter(tx.status_code for tx in answered).items())},
                "by_host": dict(sorted(Counter(tx.request.effective_host.lower()
                                               for tx in http.transactions).items())),
                "slowest": [dict(zip(INDEX_COLUMNS, index_row(tx))) for tx in slowest],
            }

        flows = report.get(EncryptedFlowsResult)
        if flows is not None and flows.flows:
            context["encrypted_overview"] = {
                "flows": len(flows.flows),
                "by_inferred_type": flows.by_label(),
                "note": "Types are inferred from traffic shape only; use the encrypted-flow tools for details.",
            }
        return context

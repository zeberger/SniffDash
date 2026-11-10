"""HTTP query tools: the four required question types (Req 32) as exact lookups."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sniffdash.analysis.analyzers.http import HttpStreamReconstructor
from sniffdash.domain.models import HttpTransaction
from sniffdash.domain.results import HttpAnalysisResult
from sniffdash.llm.answer import format_ts
from sniffdash.llm.redaction import redact
from sniffdash.llm.tools.base import QueryTool, ToolArgumentError, ToolContext, register_tool


def transaction_row(tx: HttpTransaction) -> dict[str, Any]:
    """Everything needed to state AND cite a fact about one transaction."""
    req, resp = tx.request, tx.response
    return {
        "transaction_id": tx.id,
        "method": req.method,
        "host": req.effective_host,
        "uri": req.uri,
        "client": str(req.src),
        "server": str(req.dst),
        "request_frame": req.frame_number,
        "request_time": format_ts(req.timestamp),
        "response_frame": resp.frame_number if resp else None,
        "response_time": format_ts(resp.timestamp) if resp else None,
        "status": resp.status_code if resp else None,
        "reason": resp.reason if resp else None,
        "response_time_ms": round(tx.response_time_ms, 3) if resp else None,
    }


def normalize_host(host: str) -> str:
    """'HTTP://Example.com:80/x' → 'example.com'."""
    host = host.strip().lower()
    host = host.split("://", 1)[-1].split("/", 1)[0]
    if host.count(":") == 1:  # host:port (an IPv6 address has several colons)
        host = host.split(":", 1)[0]
    return host


def _http(ctx: ToolContext) -> HttpAnalysisResult:
    http = ctx.report.get(HttpAnalysisResult)
    if http is None or not http.transactions:
        raise ToolArgumentError("This capture contains no HTTP transactions.")
    return http


def _limit(args: Mapping[str, Any], default: int, maximum: int) -> int:
    try:
        return max(1, min(maximum, int(args.get("limit", default))))
    except (TypeError, ValueError):
        raise ToolArgumentError("'limit' must be an integer") from None


@register_tool
class SlowestHttpRequests(QueryTool):
    name = "slowest_http_requests"
    description = ("HTTP transactions ordered by response time, slowest first (answered ones only). "
                   "Use for any question about slow, fast or delayed requests.")
    parameters = {"type": "object", "properties": {
        "limit": {"type": "integer", "description": "How many to return (1-20, default 5)."}}}

    def run(self, args, ctx):
        answered = [tx for tx in _http(ctx).transactions if tx.is_complete]
        ranked = sorted(answered, key=lambda tx: -tx.response_time_ms)
        return {"slowest": [transaction_row(tx) for tx in ranked[: _limit(args, 5, 20)]],
                "unanswered_not_ranked": len(_http(ctx).transactions) - len(answered)}


@register_tool
class CountRequestsByHost(QueryTool):
    name = "count_requests_by_host"
    description = ("Count HTTP requests sent to a host (case-insensitive; port and scheme ignored) "
                   "and list them with frame numbers.")
    parameters = {"type": "object", "properties": {
        "host": {"type": "string", "description": "Host name or IP, e.g. example.com"}},
        "required": ["host"]}

    def run(self, args, ctx):
        host = normalize_host(str(args.get("host") or ""))
        if not host:
            raise ToolArgumentError("'host' is required")
        matches = [tx for tx in _http(ctx).transactions if normalize_host(tx.request.effective_host) == host]
        return {"host": host, "count": len(matches), "transactions": [transaction_row(tx) for tx in matches]}


@register_tool
class StatusCodeSummary(QueryTool):
    name = "status_code_summary"
    description = ("HTTP response status codes across the capture (or for one host): counts per code, "
                   "unanswered requests, and the transactions behind each code.")
    parameters = {"type": "object", "properties": {
        "host": {"type": "string", "description": "Optional: only this host."}}}

    def run(self, args, ctx):
        txs = list(_http(ctx).transactions)
        if args.get("host"):
            host = normalize_host(str(args["host"]))
            txs = [tx for tx in txs if normalize_host(tx.request.effective_host) == host]
        by_status: dict[str, list[dict[str, Any]]] = {}
        for tx in txs:
            key = str(tx.status_code) if tx.is_complete else "unanswered"
            by_status.setdefault(key, []).append(transaction_row(tx))
        return {"counts": {k: len(v) for k, v in sorted(by_status.items())},
                "transactions_by_status": dict(sorted(by_status.items())),
                "orphan_responses": len(_http(ctx).orphan_responses)}


@register_tool
class GetTransaction(QueryTool):
    name = "get_transaction"
    description = ("Full detail of one HTTP transaction, like Wireshark's 'Follow HTTP Stream': request and "
                   "response text (credentials redacted, bodies truncated) and the TCP frames involved. "
                   "Identify it by transaction_id (e.g. tx-4) or by any of its frame numbers.")
    parameters = {"type": "object", "properties": {
        "transaction_id": {"type": "string", "description": "e.g. tx-4"},
        "frame_number": {"type": "integer", "description": "A request or response frame number."}}}

    def run(self, args, ctx):
        http = _http(ctx)
        tx = None
        if args.get("transaction_id"):
            tx = next((t for t in http.transactions if t.id == str(args["transaction_id"]).strip()), None)
        elif args.get("frame_number") is not None:
            tx = http.find_by_frame(int(args["frame_number"]))
        else:
            raise ToolArgumentError("Give transaction_id or frame_number")
        if tx is None:
            raise ToolArgumentError("No HTTP transaction matches that id or frame number.")
        view = HttpStreamReconstructor().reconstruct(tx, ctx.repo)
        return {**transaction_row(tx), "request_text": redact(view.request_text),
                "response_text": redact(view.response_text), "stream_frames": list(view.frame_numbers)}

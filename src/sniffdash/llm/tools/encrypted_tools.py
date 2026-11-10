"""Encrypted-flow tools: HTTPS traffic characterization from metadata only."""

from __future__ import annotations

from typing import Any

from sniffdash.domain.results import EncryptedFlow, EncryptedFlowsResult
from sniffdash.llm.answer import format_ts
from sniffdash.llm.tools.base import QueryTool, ToolArgumentError, register_tool

INFERENCE_NOTE = ("The traffic type is an INFERENCE from packet sizes and timing (the content is encrypted). "
                  "Present it as likely, not certain, and mention the reasons.")


def flow_row(flow: EncryptedFlow, detailed: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "stream_id": flow.stream_id, "client": str(flow.client), "server": str(flow.server),
        "server_name_sni": flow.sni, "inferred_type": flow.label, "reasons": list(flow.reasons),
        "first_frame": flow.first_frame, "first_time": format_ts(flow.start_ts),
        "last_frame": flow.last_frame, "last_time": format_ts(flow.end_ts),
        "duration_s": round(flow.duration_s, 3), "bytes_down": flow.bytes_down, "bytes_up": flow.bytes_up,
        "bursts": flow.burst_count,
    }
    if detailed:
        row |= {
            "packets_down": flow.packets_down, "packets_up": flow.packets_up,
            "down_packet_size": {"mean": round(flow.down_size_mean, 1), "median": flow.down_size_median,
                                 "max": flow.down_size_max},
            "inter_arrival_s": {"mean": round(flow.iat_mean, 6), "median": round(flow.iat_median, 6),
                                "p95": round(flow.iat_p95, 6), "cv": round(flow.iat_cv, 3)},
            "burst_mean_bytes": round(flow.burst_mean_bytes, 1),
            "largest_burst_share": round(flow.largest_burst_share, 3),
            "burst_interval_cv": None if flow.burst_interval_cv is None else round(flow.burst_interval_cv, 3),
        }
    return row


def _flows(ctx) -> EncryptedFlowsResult:
    flows = ctx.report.get(EncryptedFlowsResult)
    if flows is None or not flows.flows:
        raise ToolArgumentError("This capture contains no encrypted (TLS/HTTPS) flows with data.")
    return flows


@register_tool
class EncryptedFlows(QueryTool):
    name = "encrypted_flows"
    description = ("List encrypted HTTPS/TLS connections with their inferred traffic type (video streaming, "
                   "file/image download, API polling, interactive), volume and timing, largest first.")
    parameters = {"type": "object", "properties": {
        "limit": {"type": "integer", "description": "How many flows (1-20, default 10)."}}}

    def run(self, args, ctx):
        flows = sorted(_flows(ctx).flows, key=lambda f: -f.bytes_down)
        limit = max(1, min(20, int(args.get("limit", 10) or 10)))
        return {"note": INFERENCE_NOTE, "flows": [flow_row(f) for f in flows[:limit]]}


@register_tool
class GetEncryptedFlow(QueryTool):
    name = "get_encrypted_flow"
    description = ("All metadata features of one encrypted flow (packet sizes, inter-arrival times, bursts) "
                   "with the reasons behind its inferred traffic type.")
    parameters = {"type": "object", "properties": {
        "stream_id": {"type": "integer", "description": "TCP stream id from encrypted_flows."}},
        "required": ["stream_id"]}

    def run(self, args, ctx):
        flow = _flows(ctx).find(int(args.get("stream_id", -1)))
        if flow is None:
            raise ToolArgumentError("No encrypted flow with that stream_id.")
        return {"note": INFERENCE_NOTE, **flow_row(flow, detailed=True)}

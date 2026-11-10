"""Frame-level lookup tool: metadata of specific frames (never payload)."""

from __future__ import annotations

from sniffdash.llm.answer import format_ts
from sniffdash.llm.tools.base import QueryTool, ToolArgumentError, register_tool

MAX_FRAMES = 50


@register_tool
class GetFrames(QueryTool):
    name = "get_frames"
    description = (f"Metadata of specific frames (time, size, endpoints, protocols, TCP/UDP stream), "
                   f"up to {MAX_FRAMES} at once. Use it to verify or explain individual packets.")
    parameters = {"type": "object", "properties": {
        "frame_numbers": {"type": "array", "items": {"type": "integer"},
                          "description": "Wireshark frame numbers."}},
        "required": ["frame_numbers"]}

    def run(self, args, ctx):
        try:
            numbers = [int(n) for n in args.get("frame_numbers") or []]
        except (TypeError, ValueError):
            raise ToolArgumentError("'frame_numbers' must be a list of integers") from None
        if not numbers:
            raise ToolArgumentError("'frame_numbers' is required")
        if len(numbers) > MAX_FRAMES:
            raise ToolArgumentError(f"At most {MAX_FRAMES} frames per call")
        frames = []
        for f in ctx.repo.get_many(numbers):
            frames.append({
                "frame": f.number, "time": format_ts(f.timestamp), "length": f.length,
                "source": str(f.src) if f.src else None, "destination": str(f.dst) if f.dst else None,
                "protocols": ":".join(f.protocols), "protocol": f.highest_protocol,
                "transport": f.transport.value if f.transport else None, "stream": f.stream_id,
                "tcp_flags": (f.layer("tcp") or {}).get("flags"),
            })
        found = {f["frame"] for f in frames}
        return {"frames": frames, "not_found": [n for n in numbers if n not in found]}

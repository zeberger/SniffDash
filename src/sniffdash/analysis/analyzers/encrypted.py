"""EncryptedFlowAnalyzer → EncryptedFlowsResult: what HTTPS traffic *looks like* without decrypting it.

Encryption hides the content but not the shape of the traffic. From each TLS
connection we measure volume per direction, packet sizes, inter-arrival times and
bursts (packet trains separated by idle periods). Different applications leave
characteristic shapes:

* video streaming: long-lived, mostly downstream, fetched in regular chunks
  (players request a few seconds of video at a time), so the bursts are periodic;
* file / image download: one large downstream burst, then done;
* API polling: small request/response exchanges at a fixed interval.

The label is an explainable rule-based INFERENCE: every rule that fired is listed
in ``reasons``, and the first/last frame numbers let the user verify it.

Detection is "has a TLS layer OR uses port 443/8443", so both parsers find the
same flows (Scapy has no TLS dissector).
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from sniffdash.analysis.base import AnalysisContext, Analyzer, register_analyzer
from sniffdash.domain.models import Endpoint, Frame, Transport
from sniffdash.domain.results import EncryptedFlow, EncryptedFlowsResult
from sniffdash.repository.base import FrameRepository

HTTPS_PORTS = frozenset({443, 8443})

# Rule thresholds: one place to read, defend, and tune.
BURST_GAP_S = 0.5                    # idle time that ends a burst
VIDEO_MIN_DURATION_S = 10.0
VIDEO_MIN_BYTES_DOWN = 1_000_000
VIDEO_MIN_BURSTS = 3
VIDEO_MAX_INTERVAL_CV = 0.5          # bursts must be roughly periodic
VIDEO_MIN_DOWN_UP_RATIO = 10.0
DOWNLOAD_MIN_BYTES_DOWN = 50_000
DOWNLOAD_MIN_BURST_SHARE = 0.8       # one burst carries (almost) everything
POLLING_MIN_BURSTS = 4
POLLING_MAX_BURST_BYTES = 10_000
POLLING_MAX_INTERVAL_CV = 0.3


def _cv(values: np.ndarray) -> float:
    mean = float(values.mean()) if values.size else 0.0
    return float(values.std() / mean) if mean > 0 else 0.0


def _payload(frame: Frame) -> int:
    return int((frame.layer("tcp") or {}).get("payload_len") or 0)


def _is_https(frames: list[Frame]) -> bool:
    first = frames[0]
    ports = {first.src.port, first.dst.port} if first.src and first.dst else set()
    return bool(ports & HTTPS_PORTS) or any(f.has_protocol("tls") for f in frames)


def _client_server(frames: list[Frame]) -> tuple[Endpoint, Endpoint]:
    first = frames[0]
    if first.dst.port in HTTPS_PORTS and first.src.port not in HTTPS_PORTS:
        return first.src, first.dst
    if first.src.port in HTTPS_PORTS and first.dst.port not in HTTPS_PORTS:
        return first.dst, first.src
    for f in frames:  # ambiguous ports: whoever sent the SYN is the client
        flags = (f.layer("tcp") or {}).get("flags", "")
        if "S" in flags and "A" not in flags:
            return f.src, f.dst
    return first.src, first.dst


def classify(flow: dict) -> tuple[str, tuple[str, ...]]:
    """Apply the rules in order; return (label, the conditions that fired)."""
    duration, down, up = flow["duration"], flow["bytes_down"], flow["bytes_up"]
    bursts, interval_cv, share = flow["burst_count"], flow["burst_interval_cv"], flow["largest_burst_share"]
    ratio = down / up if up else float("inf")
    periodic = interval_cv is not None

    if (duration >= VIDEO_MIN_DURATION_S and down >= VIDEO_MIN_BYTES_DOWN and bursts >= VIDEO_MIN_BURSTS
            and periodic and interval_cv <= VIDEO_MAX_INTERVAL_CV and ratio >= VIDEO_MIN_DOWN_UP_RATIO):
        return "video_streaming", (
            f"long-lived: {duration:.1f} s ≥ {VIDEO_MIN_DURATION_S:.0f} s",
            f"large download: {down:,} B ≥ {VIDEO_MIN_BYTES_DOWN:,} B",
            f"{bursts} bursts arriving at regular intervals (CV {interval_cv:.2f} ≤ {VIDEO_MAX_INTERVAL_CV})",
            f"strongly downstream: down/up ratio {ratio:.0f} ≥ {VIDEO_MIN_DOWN_UP_RATIO:.0f}",
        )
    if down >= DOWNLOAD_MIN_BYTES_DOWN and share >= DOWNLOAD_MIN_BURST_SHARE:
        return "file_or_image_download", (
            f"download of {down:,} B ≥ {DOWNLOAD_MIN_BYTES_DOWN:,} B",
            f"{share:.0%} of it in a single burst (≥ {DOWNLOAD_MIN_BURST_SHARE:.0%})",
        )
    if (bursts >= POLLING_MIN_BURSTS and flow["max_burst_bytes"] <= POLLING_MAX_BURST_BYTES
            and periodic and interval_cv <= POLLING_MAX_INTERVAL_CV):
        return "api_polling", (
            f"{bursts} small exchanges (each ≤ {POLLING_MAX_BURST_BYTES:,} B down)",
            f"at a regular interval (CV {interval_cv:.2f} ≤ {POLLING_MAX_INTERVAL_CV})",
        )
    return "interactive_or_mixed", ("no streaming, download or polling pattern matched",)


@register_analyzer
class EncryptedFlowAnalyzer(Analyzer):
    key = EncryptedFlowsResult.key

    def analyze(self, repo: FrameRepository, ctx: AnalysisContext) -> EncryptedFlowsResult:
        streams: dict[int, list[Frame]] = defaultdict(list)
        for frame in repo.iter("tcp"):
            if frame.transport is Transport.TCP and frame.stream_id is not None and frame.src and frame.dst:
                streams[frame.stream_id].append(frame)

        flows = [self._flow(sid, frames) for sid, frames in sorted(streams.items()) if _is_https(frames)]
        return EncryptedFlowsResult(flows=tuple(f for f in flows if f is not None))

    def _flow(self, stream_id: int, frames: list[Frame]) -> EncryptedFlow | None:
        client, server = _client_server(frames)
        data = [f for f in frames if _payload(f) > 0]
        if not data:
            return None  # handshake only: no traffic shape to describe

        down = [f for f in data if f.src == server]
        up = [f for f in data if f.src == client]
        down_sizes = np.array([_payload(f) for f in down], dtype=float)
        times = np.array([f.timestamp for f in data])
        iat = np.diff(times) if times.size > 1 else np.zeros(1)

        # Bursts: split the data packets wherever the line goes idle for > BURST_GAP_S.
        burst_ids = np.concatenate(([0], np.cumsum(iat > BURST_GAP_S))) if times.size > 1 else np.zeros(1, int)
        n_bursts = int(burst_ids.max()) + 1
        down_mask = np.array([f.src == server for f in data])
        sizes = np.array([_payload(f) for f in data], dtype=float)
        burst_down = np.bincount(burst_ids, weights=sizes * down_mask, minlength=n_bursts)
        burst_starts = np.array([times[burst_ids == b].min() for b in range(n_bursts)])
        bytes_down = int(down_sizes.sum())

        features = {
            "duration": float(frames[-1].timestamp - frames[0].timestamp),
            "bytes_down": bytes_down,
            "bytes_up": int(sum(_payload(f) for f in up)),
            "burst_count": n_bursts,
            "max_burst_bytes": float(burst_down.max()),
            "largest_burst_share": float(burst_down.max() / bytes_down) if bytes_down else 0.0,
            "burst_interval_cv": _cv(np.diff(burst_starts)) if n_bursts >= 3 else None,
        }
        label, reasons = classify(features)
        sni = next((str(f.layer("tls")["sni"]) for f in frames
                    if f.layer("tls") and f.layer("tls").get("sni")), None)

        return EncryptedFlow(
            stream_id=stream_id, client=client, server=server, sni=sni,
            first_frame=frames[0].number, last_frame=frames[-1].number,
            start_ts=frames[0].timestamp, end_ts=frames[-1].timestamp,
            packets_up=sum(1 for f in frames if f.src == client),
            packets_down=sum(1 for f in frames if f.src == server),
            bytes_up=features["bytes_up"], bytes_down=bytes_down,
            down_size_mean=float(down_sizes.mean()) if down_sizes.size else 0.0,
            down_size_median=float(np.median(down_sizes)) if down_sizes.size else 0.0,
            down_size_max=int(down_sizes.max()) if down_sizes.size else 0,
            iat_mean=float(iat.mean()), iat_median=float(np.median(iat)),
            iat_p95=float(np.percentile(iat, 95)), iat_cv=_cv(iat),
            burst_count=n_bursts, burst_mean_bytes=float(burst_down.mean()),
            largest_burst_share=features["largest_burst_share"],
            burst_interval_cv=features["burst_interval_cv"],
            label=label, reasons=reasons,
        )

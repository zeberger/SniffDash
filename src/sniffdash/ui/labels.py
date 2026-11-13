"""Column headers for every table on screen: one descriptive label + hover help per column.

The facade (``AnalysisSession``) names columns for code (``rel_s``, ``bytes_down``);
this module is the only place that names them for people. Shared concepts are
defined once, so "Seconds since capture start" reads the same in every tab.
A unit test fails if a facade column reaches the screen without an entry here.
"""

from __future__ import annotations

import streamlit as st

Col = st.column_config

# --- shared concepts ----------------------------------------------------------------------
REL_S = Col.NumberColumn("Seconds since capture start", format="%.3f",
                         help="Time after the first packet, like Wireshark's default Time column.")


def _frame(label: str, help: str) -> Col.NumberColumn:
    return Col.NumberColumn(label, format="%d", help=help)


# --- one dict per table -------------------------------------------------------------------
TIMELINE = {
    "time": Col.DatetimeColumn("Interval start (UTC)", format="HH:mm:ss.SSS",
                               help="Wall-clock time at which this interval begins."),
    "rel_s": Col.NumberColumn("Interval start (s since capture start)", format="%.3f",
                              help="Seconds from the first packet to the start of this interval."),
    "packets": Col.NumberColumn("Packets in interval", format="%d", help="Packets captured during this interval."),
    "bytes": Col.NumberColumn("Bytes in interval", format="%d", help="Total size of those packets, in bytes."),
    "packets_per_s": Col.NumberColumn("Packet rate (packets/second)", format="%.1f",
                                      help="Packets in interval divided by the interval width."),
    "bytes_per_s": Col.NumberColumn("Data rate (bytes/second)", format="%.1f",
                                    help="Bytes in interval divided by the interval width."),
}

PROTOCOLS = {
    "protocol": Col.TextColumn("Protocol", help="Highest protocol layer of the packet. Each packet is counted "
                                                "once, so HTTP packets are not also counted as TCP."),
    "packets": Col.NumberColumn("Packets", format="%d", help="Number of packets whose highest layer is this protocol."),
    "share": Col.NumberColumn("Share of packets", format="percent", help="Percentage of all packets in the capture."),
}


def talkers(direction: str) -> dict:
    role = "sent" if direction == "source" else "received"
    return {
        "ip": Col.TextColumn(f"{direction.capitalize()} IP address", help=f"An address that {role} packets."),
        "packets": Col.NumberColumn(f"Packets {role}", format="%d", help=f"Number of packets this address {role}."),
    }


TRANSACTIONS = {
    "id": Col.TextColumn("Transaction ID", help="SniffDash's name for one HTTP request and its response."),
    "method": Col.TextColumn("Method", help="HTTP method of the request (GET, POST, …)."),
    "host": Col.TextColumn("Host", help="Server name from the request's Host header (or its IP address)."),
    "uri": Col.TextColumn("Path (URI)", help="The requested path and query string."),
    "source": Col.TextColumn("Client (IP:port)", help="Address and port that sent the request."),
    "destination": Col.TextColumn("Server (IP:port)", help="Address and port that received the request."),
    "status": Col.NumberColumn("Status code", format="%d", help="Numeric HTTP response code, e.g. 200 or 404. "
                                                                "Empty when no response was captured."),
    "reason": Col.TextColumn("Status text", help="The response's reason phrase, e.g. OK or Not Found."),
    "response_ms": Col.NumberColumn("Response time", format="%.1f ms",
                                    help="Time from the request packet to the first response packet."),
    "request_frame": _frame("Request frame #", "Wireshark frame number of the request."),
    "response_frame": _frame("Response frame #", "Wireshark frame number of the response."),
    "time_utc": Col.DatetimeColumn("Request time (UTC)", format="HH:mm:ss.SSS",
                                   help="Wall-clock time the request was captured."),
    "rel_s": REL_S,
}

ENCRYPTED = {
    "stream": Col.NumberColumn("TCP stream #", format="%d", help="Wireshark's tcp.stream index of the connection."),
    "client": Col.TextColumn("Client (IP:port)", help="Side that opened the connection."),
    "server": Col.TextColumn("Server (IP:port)", help="Side that accepted the connection."),
    "sni": Col.TextColumn("Server name (SNI)", help="Hostname the client asked for in the TLS handshake, "
                                                   "sent unencrypted. Empty when not present."),
    "inferred_type": Col.TextColumn("Likely traffic type", help="Inferred from packet sizes and timing only; "
                                                               "the content itself is encrypted."),
    "duration_s": Col.NumberColumn("Duration", format="%.2f s", help="From the connection's first to last packet."),
    "bytes_down": Col.NumberColumn("Bytes server → client", format="%d", help="Data downloaded by the client."),
    "bytes_up": Col.NumberColumn("Bytes client → server", format="%d", help="Data uploaded by the client."),
    "bursts": Col.NumberColumn("Data bursts", format="%d",
                               help="Groups of packets sent close together, separated by pauses."),
    "first_frame": _frame("First frame #", "Frame number of the connection's first packet."),
    "last_frame": _frame("Last frame #", "Frame number of the connection's last packet."),
    "reasons": Col.TextColumn("Why this type", help="The measurements that led to the inferred type."),
}

ISSUES = {
    "severity": Col.TextColumn("Severity", help="warning = one packet affected; error = the whole capture."),
    "frame": _frame("Frame #", "Frame the issue refers to; empty for capture-wide issues."),
    "message": Col.TextColumn("Description", help="What the parser or analyzer reported."),
}

EVIDENCE = {
    "frame": _frame("Frame #", "Wireshark frame number cited by the AI and verified against the capture."),
    "time_utc": Col.TextColumn("Time (UTC)", help="The frame's capture time, as cited (ISO-8601)."),
    "rel_s": REL_S,
    "transaction": Col.TextColumn("HTTP transaction", help="The transaction this frame belongs to, if any."),
    "protocols": Col.TextColumn("Protocol layers", help="The frame's protocol stack, outermost first."),
    "claim": Col.TextColumn("What this frame shows", help="The statement this frame is evidence for."),
}

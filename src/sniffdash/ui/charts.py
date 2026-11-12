"""Plotly figure builders: pure functions, DataFrame in → figure out (Req 26).

Design rules (from the dataviz guidance):
* every chart here shows ONE series → one hue, no legend; the title names it;
* one y-axis per chart: packets/s and bytes/s are a toggle, never a dual axis;
* thin marks: 2 px line, bars with rounded ends; recessive grid; text never in the series color;
* a hover tooltip on every mark; values directly labelled only where few (bars).

Colors are the validated reference palette's blue, with a separate step for dark
mode, chosen on purpose rather than flipped automatically.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

SERIES = {"light": "#2a78d6", "dark": "#3987e5"}
GRID = {"light": "#e9e8e4", "dark": "#383835"}
TEXT_MUTED = {"light": "#52514e", "dark": "#c3c2b7"}
FONT = "Inter, system-ui, -apple-system, Segoe UI, sans-serif"

METRICS = {
    "packets": ("packets_per_s", "Packets per second", "packets/s"),
    "bytes": ("bytes_per_s", "Bytes per second", "B/s"),
}


def _layout(fig: go.Figure, title: str, mode: str, height: int) -> go.Figure:
    fig.update_layout(
        title={"text": title, "x": 0, "xanchor": "left", "font": {"size": 15}},
        height=height, margin={"l": 8, "r": 8, "t": 44, "b": 8},
        showlegend=False, hovermode="closest",
        font={"family": FONT, "color": TEXT_MUTED[mode]},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=GRID[mode])
    fig.update_yaxes(gridcolor=GRID[mode], zeroline=False)
    return fig


def empty_figure(message: str, mode: str = "light", height: int = 260) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font={"size": 14, "color": TEXT_MUTED[mode]})
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _layout(fig, "", mode, height)


def traffic_over_time(df: pd.DataFrame, metric: str = "packets", mode: str = "light") -> go.Figure:
    """Line chart of traffic volume per time bucket (zero buckets kept, so gaps show as silence)."""
    column, title, unit = METRICS[metric]
    if df.empty:
        return empty_figure("No traffic to plot", mode)
    fig = go.Figure(go.Scatter(
        x=df["rel_s"], y=df[column], mode="lines", line={"width": 2, "color": SERIES[mode]},
        customdata=df["time"].dt.strftime("%H:%M:%S.%f").str[:-3],
        hovertemplate=f"t = %{{x:.3f}} s (%{{customdata}} UTC)<br>%{{y:,.1f}} {unit}<extra></extra>",
    ))
    fig.update_xaxes(title_text="Seconds since first packet")
    fig.update_yaxes(title_text=unit, rangemode="tozero")
    return _layout(fig, title, mode, 300)


def _hbar(labels, values, title: str, value_name: str, mode: str) -> go.Figure:
    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h", marker={"color": SERIES[mode], "cornerradius": 4},
        width=0.6, text=values, texttemplate="%{text:,}", textposition="outside",
        textfont={"color": TEXT_MUTED[mode]}, cliponaxis=False,
        hovertemplate=f"%{{y}}: %{{x:,}} {value_name}<extra></extra>",
    ))
    fig.update_yaxes(autorange="reversed", showgrid=False)          # largest on top
    fig.update_xaxes(title_text=value_name, gridcolor=GRID[mode], showgrid=True)
    return _layout(fig, title, mode, max(220, 34 * len(labels) + 90))


def protocol_breakdown(df: pd.DataFrame, mode: str = "light") -> go.Figure:
    """Packets per top-level protocol, sorted (a bar compares categories more accurately than a pie)."""
    if df.empty:
        return empty_figure("No packets", mode)
    return _hbar(df["protocol"].str.upper(), df["packets"], "Protocol breakdown", "packets", mode)


def top_talkers(df: pd.DataFrame, title: str, mode: str = "light") -> go.Figure:
    if df.empty:
        return empty_figure("No IP traffic", mode)
    return _hbar(df["ip"], df["packets"], title, "packets", mode)

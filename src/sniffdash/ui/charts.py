"""Plotly figure builders: pure functions, DataFrame in → figure out (Req 26).

Design rules (from the dataviz guidance):
* every chart here shows ONE series → one hue, no legend; the title names it;
* one y-axis per chart: packets and bytes are a toggle, never a dual axis;
* thin marks: 2 px line, bars with rounded ends; recessive grid; text never in the series color;
* a hover tooltip on every mark; values directly labelled only where few (bars).

Readability rules (walkthrough feedback, plan R1.1):
* every axis has a descriptive title, never a bare unit such as "B/s";
* labels are never clipped: ``automargin`` gives tick labels their own space, and the
  bar value axis has headroom for the numbers printed beside the bars;
* no view ever shows data that doesn't exist: the time axis can be zoomed and panned,
  but only between the capture's first and last instant (``minallowed``/``maxallowed``);
  every other axis is fixed. Dragging pans; it never draws a zoom box.

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

METRICS = {  # metric → (count column, what is counted)
    "packets": ("packets", "Packets"),
    "bytes": ("bytes", "Bytes"),
}
BAR_HEADROOM = 1.18  # value axis ends 18% past the longest bar, so its printed value fits

# Mode bar: the time chart keeps zoom in/out + reset (bounded by the axis limits);
# fixed charts keep only "Download as PNG". Box zoom and box/lasso select never appear.
_ALWAYS_REMOVED = ["zoom2d", "select2d", "lasso2d", "autoScale2d"]
_ZOOM_BUTTONS = ["pan2d", "zoomIn2d", "zoomOut2d", "resetScale2d"]


def plot_config(fig: go.Figure) -> dict:
    """Streamlit/Plotly config matching the figure: zoom buttons only where an axis can move."""
    movable = fig.layout.xaxis.fixedrange is not True
    return {"displaylogo": False, "scrollZoom": movable,
            "modeBarButtonsToRemove": _ALWAYS_REMOVED + ([] if movable else _ZOOM_BUTTONS)}


def interval_label(seconds: float) -> str:
    """0.01 → '10 ms', 1 → '1 s', 120 → '2 min'."""
    if seconds < 1:
        return f"{round(seconds * 1000, 3):g} ms"
    if seconds < 60:
        return f"{round(seconds, 3):g} s"
    return f"{round(seconds / 60, 3):g} min"


def _layout(fig: go.Figure, title: str, mode: str, height: int) -> go.Figure:
    fig.update_layout(
        title={"text": title, "x": 0, "xanchor": "left", "font": {"size": 15}},
        height=height, margin={"l": 8, "r": 24, "t": 44, "b": 8},  # minimums; automargin grows them
        showlegend=False, hovermode="closest", dragmode=False,
        font={"family": FONT, "color": TEXT_MUTED[mode]},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=GRID[mode], automargin=True, fixedrange=True)
    fig.update_yaxes(gridcolor=GRID[mode], zeroline=False, automargin=True, fixedrange=True)
    return fig


def empty_figure(message: str, mode: str = "light", height: int = 260) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font={"size": 14, "color": TEXT_MUTED[mode]})
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _layout(fig, "", mode, height)


def traffic_over_time(df: pd.DataFrame, metric: str = "packets", mode: str = "light", *,
                      interval_s: float = 1.0, duration_s: float = 0.0) -> go.Figure:
    """Line chart of traffic per time interval (empty intervals kept, so gaps show as silence).

    Counts per interval, not per-second rates: on a 0.5 s capture split into 10 ms
    intervals, 2 packets read as "2", not as a misleading "200 packets/s".
    """
    column, what = METRICS[metric]
    if df.empty:
        return empty_figure("No traffic to plot", mode)
    interval = interval_label(interval_s)
    fig = go.Figure(go.Scatter(
        x=df["rel_s"], y=df[column], mode="lines", line={"width": 2, "color": SERIES[mode]},
        customdata=df["time"].dt.strftime("%H:%M:%S.%f").str[:-3],
        hovertemplate=(f"%{{x:.3f}} s after capture start (%{{customdata}} UTC)"
                       f"<br>%{{y:,}} {what.lower()} in this {interval} interval<extra></extra>"),
    ))
    _layout(fig, f"{what} per {interval} interval", mode, 300)
    # Bounds: the capture's own span. Zoom and pan stop there, so empty time is never shown.
    lo = min(0.0, float(df["rel_s"].min()))
    hi = max(float(duration_s), float(df["rel_s"].max())) or interval_s
    fig.update_xaxes(title_text="Time since capture start (seconds)", fixedrange=False,
                     range=[lo, hi], minallowed=lo, maxallowed=hi)
    fig.update_yaxes(title_text=f"{what} in interval", rangemode="tozero")
    fig.update_layout(dragmode="pan")  # dragging moves the view; it never draws a zoom box
    return fig


def _hbar(labels, values, title: str, category_name: str, mode: str, customdata=None,
          hover_extra: str = "") -> go.Figure:
    values = list(values)
    fig = go.Figure(go.Bar(
        x=values, y=list(labels), orientation="h", marker={"color": SERIES[mode], "cornerradius": 4},
        width=0.6, text=values, texttemplate="%{text:,}", textposition="outside",
        textfont={"color": TEXT_MUTED[mode]}, cliponaxis=False, customdata=customdata,
        hovertemplate=f"%{{y}}: %{{x:,}} packets{hover_extra}<extra></extra>",
    ))
    _layout(fig, title, mode, max(220, 34 * len(values) + 110))
    fig.update_yaxes(title_text=category_name, autorange="reversed", showgrid=False)  # largest on top
    fig.update_xaxes(title_text="Number of packets", gridcolor=GRID[mode], showgrid=True,
                     range=[0, max(values) * BAR_HEADROOM])
    return fig


def protocol_breakdown(df: pd.DataFrame, mode: str = "light") -> go.Figure:
    """Packets per top-level protocol, sorted (a bar compares categories more accurately than a pie)."""
    if df.empty:
        return empty_figure("No packets", mode)
    return _hbar(df["protocol"].str.upper(), df["packets"], "Packets per protocol",
                 "Protocol (highest layer of each packet)", mode,
                 customdata=df["share"], hover_extra=" (%{customdata:.1%} of all packets)")


def top_talkers(df: pd.DataFrame, title: str, mode: str = "light", *,
                category_name: str = "IP address") -> go.Figure:
    if df.empty:
        return empty_figure("No IP traffic", mode)
    return _hbar(df["ip"], df["packets"], title, category_name, mode)

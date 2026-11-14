#!/usr/bin/env python3
"""Plot a benchmark experiment from its summary.csv file."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch


MODES = ("plaintext", "tls", "e2e")
MODE_LABELS = {"plaintext": "Plaintext", "tls": "TLS 1.3", "e2e": "TLS + E2E"}
MODE_COLORS = {"plaintext": "#4C78A8", "tls": "#F58518", "e2e": "#54A24B"}
FALLBACK_COLORS = ("#B279A2", "#E45756", "#72B7B2", "#9D755D")
METRICS = (
    "setup_ms",
    "message_latency_ms",
    "client_cpu_ms_per_message",
    "relay_cpu_ms_per_message",
    "wire_ratio",
)
REQUIRED_COLUMNS = ("rtt_ms", "mode", "size_bytes")


def finite_number(raw: object, *, field: str, row_number: int) -> float | None:
    """Return a finite float, preserving missing and non-finite data as None."""
    if raw is None or not str(raw).strip():
        return None
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ValueError(
            f"summary.csv row {row_number}: invalid {field} value {raw!r}"
        ) from exc
    if not math.isfinite(value):
        return None
    if field.endswith("_sample_sd") and value < 0:
        raise ValueError(
            f"summary.csv row {row_number}: negative sample SD in {field}"
        )
    return value


def load_summary(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise ValueError(f"summary file is missing: {path}")

    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        fieldnames = reader.fieldnames or []
        missing = [name for name in REQUIRED_COLUMNS if name not in fieldnames]
        if missing:
            raise ValueError(
                f"{path} is missing required column(s): {', '.join(missing)}"
            )

        rows: list[dict[str, object]] = []
        for row_number, raw in enumerate(reader, start=2):
            if not any(str(value or "").strip() for value in raw.values()):
                continue
            try:
                row: dict[str, object] = {
                    "condition": raw.get("condition") or "",
                    "rtt_ms": int(str(raw["rtt_ms"]).strip()),
                    "mode": str(raw["mode"] or "").strip(),
                    "size_bytes": int(str(raw["size_bytes"]).strip()),
                }
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"{path} row {row_number}: invalid RTT, mode, or payload size"
                ) from exc
            if not row["mode"]:
                raise ValueError(f"{path} row {row_number}: mode is empty")
            for metric in METRICS:
                for suffix in ("mean", "sample_sd"):
                    field = f"{metric}_{suffix}"
                    row[field] = finite_number(
                        raw.get(field), field=field, row_number=row_number
                    )
            rows.append(row)

    if not rows:
        raise ValueError(f"summary file is empty: {path}")
    return rows


def smoke_context(experiment_dir: Path) -> tuple[str | None, str]:
    """Return a title qualifier and caption for local/reduced smoke configs."""
    manifest_path = experiment_dir / "manifest.json"
    if not manifest_path.is_file():
        return None, ""
    try:
        with manifest_path.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Warning: could not read {manifest_path}: {exc}", file=sys.stderr)
        return None, ""

    config = manifest.get("config")
    if not isinstance(config, dict):
        config = {}
    environment = config.get("environment", manifest.get("environment"))
    local = environment == "local"
    reduced_flags = config.get("reduced_from_project_defaults")
    reduced = isinstance(reduced_flags, dict) and any(
        value is True for value in reduced_flags.values()
    )
    if not local and not reduced:
        return None, ""

    title = "Local smoke" if local else "Reduced smoke"
    details = []
    if local:
        details.append("local environment")
    if reduced:
        details.append("reduced benchmark configuration")
    messages = config.get("messages")
    runs = config.get("runs")
    if messages is not None or runs is not None:
        counts = []
        if messages is not None:
            counts.append(f"{messages} messages")
        if runs is not None:
            counts.append(f"{runs} run(s) per condition")
        details.append(", ".join(counts))
    return title, f"{title}: " + "; ".join(details) + "."


def ordered_modes(rows: Sequence[dict[str, object]]) -> list[str]:
    present = {str(row["mode"]) for row in rows}
    ordered = [mode for mode in MODES if mode in present]
    ordered.extend(sorted(present.difference(MODES)))
    return ordered


def mode_label(mode: str) -> str:
    return MODE_LABELS.get(mode, mode.replace("_", " ").title())


def mode_color(mode: str, index: int) -> str:
    return MODE_COLORS.get(mode, FALLBACK_COLORS[index % len(FALLBACK_COLORS)])


def size_label(size: int) -> str:
    return f"{size:,} B"


def style_axis(axis: plt.Axes) -> None:
    axis.set_axisbelow(True)
    axis.grid(axis="y", color="#D9D9D9", linewidth=0.8, alpha=0.8)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)


def add_error_bar(
    axis: plt.Axes, x: float, y: float, sample_sd: float | None, color: str = "#333333"
) -> None:
    """Draw one error bar only when its summary contains a sample SD."""
    if sample_sd is None:
        return
    axis.errorbar(
        [x],
        [y],
        yerr=[sample_sd],
        fmt="none",
        ecolor=color,
        elinewidth=1.1,
        capsize=3.5,
        capthick=1.1,
        zorder=5,
    )


def finish_figure(
    fig: plt.Figure,
    path: Path,
    title: str,
    context_title: str | None,
    context_caption: str,
    note: str,
    legend_handles: Sequence[Patch | Line2D] = (),
) -> None:
    if context_title:
        title = f"{title} — {context_title}"
    fig.suptitle(title, fontsize=16, fontweight="bold", y=0.98)
    if legend_handles:
        fig.legend(
            handles=list(legend_handles),
            loc="upper center",
            bbox_to_anchor=(0.5, 0.90),
            ncol=min(len(legend_handles), 5),
            frameon=False,
            fontsize=10,
        )
    caption = f"{context_caption}\n{note}" if context_caption else note
    fig.text(
        0.5,
        0.025,
        caption,
        ha="center",
        va="bottom",
        fontsize=9,
        color="#444444",
        linespacing=1.4,
    )
    fig.tight_layout(rect=(0.02, 0.15, 0.98, 0.81 if legend_handles else 0.88))
    try:
        fig.savefig(path, dpi=300, facecolor="white")
    finally:
        plt.close(fig)
    print(f"Saved {path.resolve()}")


def plot_setup_vs_rtt(
    rows: Sequence[dict[str, object]],
    output: Path,
    context_title: str | None,
    context_caption: str,
) -> None:
    sizes = sorted({int(row["size_bytes"]) for row in rows})
    modes = ordered_modes(rows)
    fig, axes = plt.subplots(
        1,
        len(sizes),
        figsize=(max(7.0, 5.0 * len(sizes)), 5.8),
        sharey=True,
        squeeze=False,
    )

    for axis, size in zip(axes[0], sizes):
        size_rows = [row for row in rows if row["size_bytes"] == size]
        rtts = sorted({int(row["rtt_ms"]) for row in size_rows})
        plotted = False
        for mode_index, mode in enumerate(modes):
            points = []
            for rtt in rtts:
                matches = [
                    row
                    for row in size_rows
                    if row["rtt_ms"] == rtt and row["mode"] == mode
                ]
                if not matches:
                    continue
                mean = matches[0]["setup_ms_mean"]
                if mean is None:
                    continue
                points.append((rtt, float(mean), matches[0]["setup_ms_sample_sd"]))
            if not points:
                continue
            plotted = True
            color = mode_color(mode, mode_index)
            axis.plot(
                [point[0] for point in points],
                [point[1] for point in points],
                marker="o",
                markersize=6,
                linewidth=2,
                color=color,
            )
            for rtt, mean, sample_sd in points:
                add_error_bar(axis, rtt, mean, sample_sd, color)
        axis.set_title(f"Payload: {size_label(size)}", fontsize=12)
        axis.set_xlabel("Configured network RTT (ms)")
        axis.set_xticks(rtts)
        axis.set_ylim(bottom=0)
        style_axis(axis)
        if not plotted:
            axis.text(
                0.5,
                0.5,
                "No finite setup data",
                transform=axis.transAxes,
                ha="center",
                va="center",
                color="#666666",
            )
    axes[0][0].set_ylabel("Setup time (ms)")
    handles = [
        Line2D(
            [0],
            [0],
            color=mode_color(mode, index),
            marker="o",
            linewidth=2,
            label=mode_label(mode),
        )
        for index, mode in enumerate(modes)
    ]
    finish_figure(
        fig,
        output / "setup_vs_rtt.png",
        "Connection setup vs. network RTT",
        context_title,
        context_caption,
        "Points are successful-run means for each condition. Error bars show the reported "
        "sample SD only where available; missing measurements are omitted.",
        handles,
    )


def lookup_rows(
    rows: Sequence[dict[str, object]],
) -> dict[tuple[int, str, int], dict[str, object]]:
    return {
        (int(row["rtt_ms"]), str(row["mode"]), int(row["size_bytes"])): row
        for row in rows
    }


def plot_metric_by_size(
    rows: Sequence[dict[str, object]],
    output: Path,
    context_title: str | None,
    context_caption: str,
    *,
    metric: str,
    filename: str,
    title: str,
    ylabel: str,
    reference_one: bool = False,
) -> None:
    rtts = sorted({int(row["rtt_ms"]) for row in rows})
    sizes = sorted({int(row["size_bytes"]) for row in rows})
    modes = ordered_modes(rows)
    indexed = lookup_rows(rows)
    mean_field = f"{metric}_mean"
    sd_field = f"{metric}_sample_sd"
    width = 0.8 / len(modes)
    fig, axes = plt.subplots(
        1,
        len(rtts),
        figsize=(max(7.0, 5.0 * len(rtts)), 5.8),
        sharey=True,
        squeeze=False,
    )

    for axis, rtt in zip(axes[0], rtts):
        plotted = False
        for mode_index, mode in enumerate(modes):
            color = mode_color(mode, mode_index)
            for size_index, size in enumerate(sizes):
                row = indexed.get((rtt, mode, size))
                if row is None or row[mean_field] is None:
                    continue
                mean = float(row[mean_field])
                position = size_index + (mode_index - (len(modes) - 1) / 2) * width
                axis.bar(
                    [position],
                    [mean],
                    width=width * 0.9,
                    color=color,
                    edgecolor="white",
                    linewidth=0.6,
                    zorder=3,
                )
                add_error_bar(axis, position, mean, row[sd_field])
                plotted = True
        if reference_one:
            axis.axhline(
                1.0,
                color="#555555",
                linestyle="--",
                linewidth=1.1,
                zorder=2,
            )
        axis.set_title(f"Network RTT: {rtt} ms", fontsize=12)
        axis.set_xlabel("Payload size")
        axis.set_xticks(range(len(sizes)), [size_label(size) for size in sizes])
        axis.set_ylim(bottom=0)
        style_axis(axis)
        if not plotted:
            axis.text(
                0.5,
                0.5,
                "No finite data",
                transform=axis.transAxes,
                ha="center",
                va="center",
                color="#666666",
            )
    axes[0][0].set_ylabel(ylabel)
    handles: list[Patch | Line2D] = [
        Patch(
            facecolor=mode_color(mode, index),
            edgecolor="none",
            label=mode_label(mode),
        )
        for index, mode in enumerate(modes)
    ]
    if reference_one:
        handles.append(
            Line2D(
                [0],
                [0],
                color="#555555",
                linestyle="--",
                linewidth=1.1,
                label="No overhead (1×)",
            )
        )
    note = (
        "Bars are successful-run means. Error bars show the reported sample SD only "
        "where available; missing measurements are omitted."
    )
    if reference_one:
        note += " The dashed line marks a wire ratio of 1."
    finish_figure(
        fig,
        output / filename,
        title,
        context_title,
        context_caption,
        note,
        handles,
    )


def plot_cpu_overhead(
    rows: Sequence[dict[str, object]],
    output: Path,
    context_title: str | None,
    context_caption: str,
) -> None:
    rtts = sorted({int(row["rtt_ms"]) for row in rows})
    sizes = sorted({int(row["size_bytes"]) for row in rows})
    modes = ordered_modes(rows)
    indexed = lookup_rows(rows)
    width = 0.8 / len(modes)
    incomplete = 0
    fig, axes = plt.subplots(
        1,
        len(rtts),
        figsize=(max(7.0, 5.0 * len(rtts)), 5.8),
        sharey=True,
        squeeze=False,
    )

    for axis, rtt in zip(axes[0], rtts):
        plotted = False
        for mode_index, mode in enumerate(modes):
            color = mode_color(mode, mode_index)
            for size_index, size in enumerate(sizes):
                row = indexed.get((rtt, mode, size))
                if row is None:
                    continue
                client = row["client_cpu_ms_per_message_mean"]
                relay = row["relay_cpu_ms_per_message_mean"]
                if client is None or relay is None:
                    if client is not None or relay is not None:
                        incomplete += 1
                    continue
                client_mean = float(client)
                relay_mean = float(relay)
                position = size_index + (mode_index - (len(modes) - 1) / 2) * width
                axis.bar(
                    [position],
                    [client_mean],
                    width=width * 0.9,
                    color=color,
                    edgecolor="white",
                    linewidth=0.6,
                    zorder=3,
                )
                axis.bar(
                    [position],
                    [relay_mean],
                    width=width * 0.9,
                    bottom=[client_mean],
                    color=color,
                    alpha=0.48,
                    hatch="//",
                    edgecolor="white",
                    linewidth=0.6,
                    zorder=3,
                )
                add_error_bar(
                    axis,
                    position,
                    client_mean / 2,
                    row["client_cpu_ms_per_message_sample_sd"],
                )
                add_error_bar(
                    axis,
                    position,
                    client_mean + relay_mean / 2,
                    row["relay_cpu_ms_per_message_sample_sd"],
                )
                plotted = True
        axis.set_title(f"Network RTT: {rtt} ms", fontsize=12)
        axis.set_xlabel("Payload size")
        axis.set_xticks(range(len(sizes)), [size_label(size) for size in sizes])
        axis.set_ylim(bottom=0)
        style_axis(axis)
        if not plotted:
            axis.text(
                0.5,
                0.5,
                "No complete client + relay CPU data",
                transform=axis.transAxes,
                ha="center",
                va="center",
                color="#666666",
            )
    axes[0][0].set_ylabel("CPU time (ms/message)")
    handles: list[Patch | Line2D] = [
        Patch(
            facecolor=mode_color(mode, index),
            edgecolor="none",
            label=mode_label(mode),
        )
        for index, mode in enumerate(modes)
    ]
    handles.extend(
        [
            Patch(facecolor="#777777", edgecolor="none", label="Client (solid)"),
            Patch(
                facecolor="#BBBBBB",
                edgecolor="white",
                hatch="//",
                label="Relay (hatched)",
            ),
        ]
    )
    finish_figure(
        fig,
        output / "cpu_overhead.png",
        "Client + relay CPU overhead per message",
        context_title,
        context_caption,
        "Stacked bars require finite client and relay means. Component error bars are centered "
        "within their segments and appear only with a reported sample SD; incomplete stacks "
        "and other missing measurements are omitted.",
        handles,
    )
    if incomplete:
        print(
            f"Warning: omitted {incomplete} CPU condition(s) with only one finite component.",
            file=sys.stderr,
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate benchmark plots from EXPERIMENT_DIR/summary.csv."
    )
    parser.add_argument("experiment_dir", type=Path, metavar="EXPERIMENT_DIR")
    parser.add_argument(
        "--output",
        type=Path,
        metavar="DIR",
        help="plot directory (default: EXPERIMENT_DIR/plots)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    experiment_dir = args.experiment_dir.expanduser()
    output = args.output.expanduser() if args.output else experiment_dir / "plots"
    try:
        rows = load_summary(experiment_dir / "summary.csv")
        output.mkdir(parents=True, exist_ok=True)
        context_title, context_caption = smoke_context(experiment_dir)
        plot_setup_vs_rtt(rows, output, context_title, context_caption)
        plot_metric_by_size(
            rows,
            output,
            context_title,
            context_caption,
            metric="message_latency_ms",
            filename="latency_by_size.png",
            title="Message latency by payload size",
            ylabel="Mean message round-trip latency (ms)",
        )
        plot_cpu_overhead(rows, output, context_title, context_caption)
        if any(row["wire_ratio_mean"] is not None for row in rows):
            plot_metric_by_size(
                rows,
                output,
                context_title,
                context_caption,
                metric="wire_ratio",
                filename="wire_overhead.png",
                title="Wire overhead by payload size",
                ylabel="Wire bytes / payload bytes",
                reference_one=True,
            )
        else:
            print(
                f"Skipping {output / 'wire_overhead.png'}: "
                "summary.csv contains no finite wire ratios."
            )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

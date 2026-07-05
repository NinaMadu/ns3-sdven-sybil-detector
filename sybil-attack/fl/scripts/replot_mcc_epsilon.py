#!/usr/bin/env python3
"""Replot MCC from an existing metrics_results.csv with epsilon regularization.

This does not rerun ns-3. It reads M5_TP/M5_FP/M5_FN/M5_TN and computes:

  MCC_eps = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN) + epsilon)

Example:
  python3 sybil-attack/fl/scripts/replot_mcc_epsilon.py \
    --results sybil-attack/fl/evaluation/fl_final_20s/metrics_results.csv
"""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Iterable, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True, help="Path to metrics_results.csv")
    parser.add_argument("--epsilon", type=float, default=1e-9)
    parser.add_argument("--metric-name", default="M5_MCC_epsilon")
    parser.add_argument("--out-csv", default="")
    parser.add_argument("--out-svg", default="")
    return parser.parse_args()


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def read_rows(path: Path) -> List[dict]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_rows(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def add_epsilon_mcc(rows: List[dict], metric_name: str, epsilon: float) -> None:
    for row in rows:
        tp = safe_float(row.get("M5_TP"))
        fp = safe_float(row.get("M5_FP"))
        fn = safe_float(row.get("M5_FN"))
        tn = safe_float(row.get("M5_TN"))
        smooth = 2.0 * epsilon
        numerator = (tp + smooth) * (tn + smooth) - (fp + smooth) * (fn + smooth)
        product = (
            (tp + fp + smooth)
            * (tp + fn + smooth)
            * (tn + fp + smooth)
            * (tn + fn + smooth)
        )
        row[metric_name] = numerator / math.sqrt(product) if product > 0 else 0.0


def finite_values(values: Iterable[object]) -> List[float]:
    out = []
    for value in values:
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number):
            out.append(number)
    return out


def plot_svg(rows: List[dict], metric: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    percentages = sorted({int(float(r["attack_percentage"])) for r in rows})
    attack_types = sorted({int(float(r["attack_type"])) for r in rows})
    values = finite_values(r.get(metric) for r in rows)
    if not percentages or not attack_types or not values:
        raise SystemExit(f"No finite values found for {metric}")

    width, height = 1000, 650
    left, right, top, bottom = 90, 230, 55, 90
    plot_w = width - left - right
    plot_h = height - top - bottom
    x_min, x_max = min(percentages), max(percentages)
    y_min, y_max = -1.0, 1.0
    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf", "#8c564b"]

    def x_scale(p: int) -> float:
        return left + (plot_w / 2 if x_max == x_min else (p - x_min) * plot_w / (x_max - x_min))

    def y_scale(v: float) -> float:
        return top + (y_max - v) * plot_h / (y_max - y_min)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2}" y="28" text-anchor="middle" font-family="Arial" font-size="21" font-weight="700">{metric} vs Attack Percentage</text>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>',
        f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>',
    ]
    for y in [-1.0, -0.5, 0.0, 0.5, 1.0]:
        yy = y_scale(y)
        lines.append(f'<line x1="{left}" y1="{yy:.2f}" x2="{left+plot_w}" y2="{yy:.2f}" stroke="#ddd"/>')
        lines.append(f'<text x="{left-12}" y="{yy+5:.2f}" text-anchor="end" font-family="Arial" font-size="13">{y:.1f}</text>')
    for p in percentages:
        xx = x_scale(p)
        lines.append(f'<line x1="{xx:.2f}" y1="{top+plot_h}" x2="{xx:.2f}" y2="{top+plot_h+6}" stroke="#222"/>')
        lines.append(f'<text x="{xx:.2f}" y="{top+plot_h+26}" text-anchor="middle" font-family="Arial" font-size="13">{p}</text>')
    lines.append(f'<text x="{left+plot_w/2}" y="{height-30}" text-anchor="middle" font-family="Arial" font-size="16">Attack Percentage (%)</text>')
    lines.append(f'<text x="24" y="{top+plot_h/2}" text-anchor="middle" font-family="Arial" font-size="16" transform="rotate(-90 24 {top+plot_h/2})">MCC</text>')

    for idx, attack_type in enumerate(attack_types):
        color = colors[idx % len(colors)]
        series = sorted((r for r in rows if int(float(r["attack_type"])) == attack_type), key=lambda r: int(float(r["attack_percentage"])))
        points = []
        for r in series:
            value = safe_float(r.get(metric), float("nan"))
            if math.isfinite(value):
                points.append((x_scale(int(float(r["attack_percentage"]))), y_scale(value), value))
        if len(points) >= 2:
            lines.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="' + " ".join(f"{x:.2f},{y:.2f}" for x, y, _ in points) + '"/>')
        for x, y, value in points:
            lines.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4.5" fill="{color}"><title>Attack {attack_type}: {metric}={value:.6g}</title></circle>')
        legend_x = left + plot_w + 35
        legend_y = top + 25 + idx * 28
        lines.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x+26}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{legend_x+36}" y="{legend_y+5}" font-family="Arial" font-size="14">Attack {attack_type}</text>')

    lines.append("</svg>")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    results_path = Path(args.results)
    rows = read_rows(results_path)
    if not rows:
        raise SystemExit(f"No rows in {results_path}")
    add_epsilon_mcc(rows, args.metric_name, args.epsilon)

    out_csv = Path(args.out_csv) if args.out_csv else results_path.with_name(results_path.stem + "_with_mcc_epsilon.csv")
    out_svg = Path(args.out_svg) if args.out_svg else results_path.parent / "mcc_epsilon_vs_attack_percentage.svg"
    write_rows(out_csv, rows)
    plot_svg(rows, args.metric_name, out_svg)
    print(f"CSV:  {out_csv}")
    print(f"Plot: {out_svg}")


if __name__ == "__main__":
    main()
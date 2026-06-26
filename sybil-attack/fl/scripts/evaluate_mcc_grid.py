#!/usr/bin/env python3
"""
Run FL detection over an attack-type/attack-percentage grid and plot MCC.

Example:
  python3 sybil-attack/fl/scripts/evaluate_mcc_grid.py \
    --attack-types 1,2,3,4,5,6 \
    --percentages 0,20,40,60,80,100 \
    --sim-time 120 \
    --mobility-mode 5 \
    --controllers 4

Outputs:
  sybil-attack/fl/evaluation/mcc_results.csv
  sybil-attack/fl/evaluation/mcc_vs_attack_percentage.svg
  sybil-attack/fl/evaluation/raw_outputs/attackX_pctY/*.csv
"""

from __future__ import annotations

import argparse
import csv
import math
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional


METRIC_FILES = [
    "metrics_summary.csv",
    "metrics_M5_M6_detection_quality.csv",
    "metrics_M7_revocation_latency.csv",
    "metrics_M8_comm_overhead.csv",
    "metrics_M9_fl_convergence.csv",
    "metrics_M10_complexity.csv",
    "metrics_tier_summary.csv",
]


def parse_csv_int_list(text: str) -> List[int]:
    return [int(part.strip()) for part in text.split(",") if part.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-types", default="1,2,3,4,5,6")
    parser.add_argument("--percentages", default="0,20,40,60,80,100")
    parser.add_argument("--sim-time", type=float, default=120.0)
    parser.add_argument("--mobility-mode", type=int, default=5)
    parser.add_argument("--controllers", type=int, default=4)
    parser.add_argument("--solution-mode", type=int, default=1)
    parser.add_argument("--sec-enabled", default="false")
    parser.add_argument("--out-dir", default="sybil-attack/fl/evaluation")
    parser.add_argument("--program", default="scratch/Sybil-Developing-Improved")
    parser.add_argument("--waf", default="./waf")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--extra-args",
        default="",
        help="Extra ns-3 args, e.g. '--beaconInterval=1.0 --rsuReportInterval=1.5'",
    )
    return parser.parse_args()


def read_cumulative_detection_metrics(path: Path) -> Dict[str, float]:
    if not path.exists():
        return {
            "mcc": float("nan"),
            "fpr": float("nan"),
            "precision": float("nan"),
            "recall": float("nan"),
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }

    rows = list(csv.DictReader(path.open(newline="")))
    if not rows:
        raise RuntimeError(f"No metric rows found in {path}")

    row = next((r for r in rows if r.get("window_label") == "CUMULATIVE"), rows[-1])
    return {
        "mcc": float(row.get("MCC", "nan")),
        "fpr": float(row.get("FPR", "nan")),
        "precision": float(row.get("Precision", "nan")),
        "recall": float(row.get("Recall", "nan")),
        "tp": int(float(row.get("TP", 0))),
        "fp": int(float(row.get("FP", 0))),
        "fn": int(float(row.get("FN", 0))),
        "tn": int(float(row.get("TN", 0))),
    }


def build_ns3_command(args: argparse.Namespace, attack_type: int, percentage: int) -> List[str]:
    attack_enabled = "false" if percentage == 0 else "true"
    sim_args = [
        args.program,
        "--routing_test=false",
        f"--mobility_mode={args.mobility_mode}",
        "--sumoAutoConfig=true",
        f"--N_Controllers={args.controllers}",
        f"--simTime={args.sim_time:g}",
        f"--sybil_attack_enabled={attack_enabled}",
        f"--sybil_attack_type={attack_type}",
        f"--sybil_attack_percentage={percentage}",
        f"--solution_mode={args.solution_mode}",
        f"--SecEnabled={args.sec_enabled}",
    ]
    if args.extra_args.strip():
        sim_args.extend(args.extra_args.strip().split())
    return [args.waf, "--run", " ".join(sim_args)]


def copy_metric_outputs(outputs_dir: Path, run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in METRIC_FILES:
        src = outputs_dir / name
        if src.exists():
            shutil.copy2(src, run_dir / name)


def write_results_csv(path: Path, rows: List[dict]) -> None:
    fieldnames = [
        "attack_type",
        "attack_percentage",
        "mcc",
        "fpr",
        "precision",
        "recall",
        "tp",
        "fp",
        "fn",
        "tn",
        "run_dir",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_existing_results(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def plot_svg(results: List[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    width, height = 1000, 650
    left, right, top, bottom = 90, 230, 55, 90
    plot_w = width - left - right
    plot_h = height - top - bottom

    percentages = sorted({int(r["attack_percentage"]) for r in results})
    attack_types = sorted({int(r["attack_type"]) for r in results})
    if not percentages or not attack_types:
        return

    x_min, x_max = min(percentages), max(percentages)
    y_min, y_max = -1.0, 1.0
    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf", "#8c564b"]

    def x_scale(p: int) -> float:
        if x_max == x_min:
            return left + plot_w / 2
        return left + (p - x_min) * plot_w / (x_max - x_min)

    def y_scale(v: float) -> float:
        return top + (y_max - v) * plot_h / (y_max - y_min)

    lines: List[str] = []
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">')
    lines.append('<rect width="100%" height="100%" fill="white"/>')
    lines.append(f'<text x="{width/2}" y="28" text-anchor="middle" font-family="Arial" font-size="22" font-weight="700">FL Detection MCC vs Attack Percentage</text>')
    lines.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>')
    lines.append(f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>')

    for y in [-1.0, -0.5, 0.0, 0.5, 1.0]:
        yy = y_scale(y)
        lines.append(f'<line x1="{left}" y1="{yy:.2f}" x2="{left+plot_w}" y2="{yy:.2f}" stroke="#ddd" stroke-width="1"/>')
        lines.append(f'<text x="{left-12}" y="{yy+5:.2f}" text-anchor="end" font-family="Arial" font-size="13">{y:.1f}</text>')

    for p in percentages:
        xx = x_scale(p)
        lines.append(f'<line x1="{xx:.2f}" y1="{top+plot_h}" x2="{xx:.2f}" y2="{top+plot_h+6}" stroke="#222"/>')
        lines.append(f'<text x="{xx:.2f}" y="{top+plot_h+26}" text-anchor="middle" font-family="Arial" font-size="13">{p}</text>')

    lines.append(f'<text x="{left+plot_w/2}" y="{height-30}" text-anchor="middle" font-family="Arial" font-size="16">Attack Percentage (%)</text>')
    lines.append(f'<text x="24" y="{top+plot_h/2}" text-anchor="middle" font-family="Arial" font-size="16" transform="rotate(-90 24 {top+plot_h/2})">MCC</text>')

    for idx, attack_type in enumerate(attack_types):
        color = colors[idx % len(colors)]
        series = sorted(
            (r for r in results if int(r["attack_type"]) == attack_type),
            key=lambda r: int(r["attack_percentage"]),
        )
        points = []
        for r in series:
            try:
                mcc = float(r["mcc"])
            except (TypeError, ValueError):
                continue
            if math.isnan(mcc):
                continue
            points.append((x_scale(int(r["attack_percentage"])), y_scale(mcc), int(r["attack_percentage"]), mcc))
        if len(points) >= 2:
            d = " ".join(f"{x:.2f},{y:.2f}" for x, y, _, _ in points)
            lines.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{d}"/>')
        for x, y, _, mcc in points:
            lines.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4.5" fill="{color}"/>')
            lines.append(f'<title>Attack {attack_type}: MCC={mcc:.4f}</title>')

        legend_x = left + plot_w + 35
        legend_y = top + 25 + idx * 28
        lines.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x+26}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<circle cx="{legend_x+13}" cy="{legend_y}" r="4" fill="{color}"/>')
        lines.append(f'<text x="{legend_x+36}" y="{legend_y+5}" font-family="Arial" font-size="14">Attack {attack_type}</text>')

    lines.append("</svg>")
    out_path.write_text("\n".join(lines))


def main() -> None:
    args = parse_args()
    attack_types = parse_csv_int_list(args.attack_types)
    percentages = parse_csv_int_list(args.percentages)
    out_dir = Path(args.out_dir)
    raw_dir = out_dir / "raw_outputs"
    outputs_dir = Path("sybil-attack/outputs")
    results_path = out_dir / "mcc_results.csv"

    results = load_existing_results(results_path) if args.skip_existing else []
    done = {(int(r["attack_type"]), int(r["attack_percentage"])) for r in results}

    for attack_type in attack_types:
        for percentage in percentages:
            run_name = f"attack{attack_type}_pct{percentage}"
            run_dir = raw_dir / run_name
            if args.skip_existing and (attack_type, percentage) in done:
                print(f"[skip] {run_name}")
                continue

            cmd = build_ns3_command(args, attack_type, percentage)
            print(f"[run] {run_name}")
            print("      " + " ".join(cmd))
            if not args.dry_run:
                subprocess.run(cmd, check=True)
                copy_metric_outputs(outputs_dir, run_dir)
                metrics = read_cumulative_detection_metrics(run_dir / "metrics_M5_M6_detection_quality.csv")
            else:
                metrics = {
                    "mcc": float("nan"),
                    "fpr": float("nan"),
                    "precision": float("nan"),
                    "recall": float("nan"),
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "tn": 0,
                }

            row = {
                "attack_type": attack_type,
                "attack_percentage": percentage,
                "mcc": metrics["mcc"],
                "fpr": metrics["fpr"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "fn": metrics["fn"],
                "tn": metrics["tn"],
                "run_dir": str(run_dir),
            }
            results = [r for r in results if not (
                int(r["attack_type"]) == attack_type and int(r["attack_percentage"]) == percentage
            )]
            results.append(row)
            results.sort(key=lambda r: (int(r["attack_type"]), int(r["attack_percentage"])))
            write_results_csv(results_path, results)
            plot_svg(results, out_dir / "mcc_vs_attack_percentage.svg")
            print(f"      MCC={metrics['mcc']} TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}")

    write_results_csv(results_path, results)
    plot_svg(results, out_dir / "mcc_vs_attack_percentage.svg")
    print(f"Results: {results_path}")
    print(f"Plot:    {out_dir / 'mcc_vs_attack_percentage.svg'}")


if __name__ == "__main__":
    main()

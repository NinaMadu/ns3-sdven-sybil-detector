#!/usr/bin/env python3
"""Run FL baseline over an attack grid and plot M1-M10 metrics."""

from __future__ import annotations

import argparse
import csv
import math
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List

METRIC_FILES = [
    "metrics_summary.csv",
    "metrics_M1_PDR.csv",
    "metrics_M2_Latency.csv",
    "metrics_M3_PacketAttraction.csv",
    "metrics_M4_Congestion.csv",
    "metrics_M5_M6_detection_quality.csv",
    "metrics_M7_revocation_latency.csv",
    "metrics_M8_comm_overhead.csv",
    "metrics_M9_fl_convergence.csv",
    "metrics_M10_complexity.csv",
    "metrics_tier_summary.csv",
]

PLOT_METRICS = [
    "M1_PDR",
    "M2_avg_latency_ms",
    "M2_p95_latency_ms",
    "M2_loss_penalized_latency_ms",
    "M3_attraction_ratio",
    "M4_congestion_ratio",
    "M5_MCC",
    "M5_precision",
    "M5_recall",
    "M6_FPR",
    "M7_avg_revocation_latency_ms",
    "M8_total_overhead_bytes",
    "M8_kb_per_event",
    "M9_final_global_loss",
    "M9_avg_mpc_overhead_ms",
    "M10_avg_wall_clock_ms",
    "M10_total_flops",
]


def parse_csv_int_list(text: str) -> List[int]:
    return [int(part.strip()) for part in text.split(",") if part.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-types", default="1,2,3,4,5,6")
    parser.add_argument("--percentages", default="20,40,60,80,100")
    parser.add_argument("--sim-time", type=float, default=120.0)
    parser.add_argument("--mobility-mode", type=int, default=5)
    parser.add_argument("--controllers", type=int, default=4)
    parser.add_argument("--solution-mode", type=int, default=1)
    parser.add_argument("--sec-enabled", default="false")
    parser.add_argument("--out-dir", default="sybil-attack/fl/evaluation")
    parser.add_argument("--program", default="scratch/Sybil-Developing-Improved")
    parser.add_argument("--waf", default="./waf")
    parser.add_argument("--outputs-dir", default="sybil-attack/outputs")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--extra-args",
        default="",
        help="Extra ns-3 args, e.g. '--beaconInterval=1.0 --rsuReportInterval=1.5'",
    )
    return parser.parse_args()


def safe_float(value: object, default: float = float("nan")) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: object, default: int = 0) -> int:
    number = safe_float(value, float("nan"))
    if math.isnan(number):
        return default
    return int(number)


def read_rows(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def read_summary_metrics(path: Path) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    for row in read_rows(path):
        key = row.get("metric", "")
        if key:
            metrics[key] = safe_float(row.get("value"))
    return metrics


def detection_metrics(path: Path) -> Dict[str, float]:
    rows = read_rows(path)
    if not rows:
        return {
            "M5_MCC": float("nan"), "M6_FPR": float("nan"),
            "M5_precision": float("nan"), "M5_recall": float("nan"),
            "M5_TP": 0, "M5_FP": 0, "M5_FN": 0, "M5_TN": 0,
        }
    cumulative = next((r for r in rows if r.get("window_label") == "CUMULATIVE"), None)
    if cumulative is not None:
        tp, fp, fn, tn = [safe_int(cumulative.get(k)) for k in ["TP", "FP", "FN", "TN"]]
    else:
        tp = sum(safe_int(r.get("TP")) for r in rows)
        fp = sum(safe_int(r.get("FP")) for r in rows)
        fn = sum(safe_int(r.get("FN")) for r in rows)
        tn = sum(safe_int(r.get("TN")) for r in rows)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    denom = math.sqrt(max(1, (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    mcc = ((tp * tn) - (fp * fn)) / denom
    return {
        "M5_MCC": mcc, "M6_FPR": fpr, "M5_precision": precision, "M5_recall": recall,
        "M5_TP": tp, "M5_FP": fp, "M5_FN": fn, "M5_TN": tn,
    }


def revocation_metrics(path: Path) -> Dict[str, float]:
    latencies = [safe_float(r.get("latency_ms")) for r in read_rows(path)]
    latencies = [v for v in latencies if not math.isnan(v)]
    return {
        "M7_avg_revocation_latency_ms": sum(latencies) / len(latencies) if latencies else float("nan"),
        "M7_revocation_events": len(latencies),
    }


def overhead_metrics(path: Path) -> Dict[str, float]:
    total_bytes = 0.0
    events = 0.0
    for row in read_rows(path):
        for key in ["evidence_bytes", "ipfs_publication_bytes", "threshold_sig_bytes", "obu_to_rsu_bytes", "rsu_to_controller_bytes"]:
            total_bytes += safe_float(row.get(key), 0.0)
        events += safe_float(row.get("detection_events"), 0.0)
    return {
        "M8_total_overhead_bytes": total_bytes,
        "M8_detection_events": events,
        "M8_kb_per_event": (total_bytes / 1024.0 / events) if events > 0 else 0.0,
    }


def fl_convergence_metrics(path: Path) -> Dict[str, float]:
    rows = read_rows(path)
    round_rows = [r for r in rows if str(r.get("round", "")).isdigit()]
    if not round_rows:
        summary = rows[-1] if rows else {}
        return {
            "M9_rounds_completed": safe_float(summary.get("rounds_completed"), 0.0),
            "M9_final_global_loss": safe_float(summary.get("global_loss")),
            "M9_avg_mpc_overhead_ms": safe_float(summary.get("avg_mpc_overhead_ms")),
        }
    last = round_rows[-1]
    return {
        "M9_rounds_completed": safe_float(last.get("rounds_completed"), safe_float(last.get("round"), 0.0)),
        "M9_final_global_loss": safe_float(last.get("global_loss")),
        "M9_avg_mpc_overhead_ms": safe_float(last.get("avg_mpc_overhead_ms")),
    }


def complexity_metrics(path: Path) -> Dict[str, float]:
    count = 0
    total_wall = 0.0
    total_flops = 0.0
    for row in read_rows(path):
        count += 1
        total_wall += safe_float(row.get("wall_clock_ms_measured"), 0.0)
        total_flops += safe_float(row.get("estimated_flops_eq3_39_to_3_41"), 0.0)
    return {
        "M10_complexity_events": count,
        "M10_avg_wall_clock_ms": total_wall / count if count else float("nan"),
        "M10_total_flops": total_flops,
        "M10_avg_flops": total_flops / count if count else float("nan"),
    }


def collect_metrics(run_dir: Path) -> Dict[str, float]:
    summary = read_summary_metrics(run_dir / "metrics_summary.csv")
    metrics: Dict[str, float] = {
        "M1_PDR": summary.get("M1_PDR", float("nan")),
        "M1_total_transmitted": summary.get("M1_total_transmitted", float("nan")),
        "M1_total_delivered": summary.get("M1_total_delivered", float("nan")),
        "M2_avg_latency_ms": summary.get("M2_avg_latency_ms", float("nan")),
        "M2_intended_avg_latency_ms": summary.get("M2_intended_avg_latency_ms", float("nan")),
        "M2_p95_latency_ms": summary.get("M2_p95_latency_ms", float("nan")),
        "M2_loss_penalized_latency_ms": summary.get("M2_loss_penalized_latency_ms", float("nan")),
        "M2_dropped_packets": summary.get("M2_dropped_packets", float("nan")),
        "M3_attraction_ratio": summary.get("M3_attraction_ratio", float("nan")),
        "M3_sybil_diverted": summary.get("M3_sybil_diverted", float("nan")),
        "M4_congestion_ratio": summary.get("M4_congestion_ratio", float("nan")),
        "M4_false_traffic_packets": summary.get("M4_false_traffic_packets", float("nan")),
        "sim_time_s": summary.get("sim_time_s", float("nan")),
    }
    metrics.update(detection_metrics(run_dir / "metrics_M5_M6_detection_quality.csv"))
    metrics.update(revocation_metrics(run_dir / "metrics_M7_revocation_latency.csv"))
    metrics.update(overhead_metrics(run_dir / "metrics_M8_comm_overhead.csv"))
    metrics.update(fl_convergence_metrics(run_dir / "metrics_M9_fl_convergence.csv"))
    metrics.update(complexity_metrics(run_dir / "metrics_M10_complexity.csv"))
    return metrics


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


def load_existing_results(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_results_csv(path: Path, rows: List[dict]) -> None:
    base = ["attack_type", "attack_percentage", "run_dir"]
    metric_fields = sorted({key for row in rows for key in row.keys() if key not in base})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=base + metric_fields)
        writer.writeheader()
        writer.writerows(rows)


def finite_values(values: Iterable[object]) -> List[float]:
    out = []
    for value in values:
        number = safe_float(value)
        if math.isfinite(number):
            out.append(number)
    return out


def plot_metric_svg(results: List[dict], metric: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    percentages = sorted({int(r["attack_percentage"]) for r in results})
    attack_types = sorted({int(r["attack_type"]) for r in results})
    values = finite_values(r.get(metric) for r in results)
    if not percentages or not attack_types or not values:
        return

    width, height = 1000, 650
    left, right, top, bottom = 95, 230, 55, 90
    plot_w = width - left - right
    plot_h = height - top - bottom
    x_min, x_max = min(percentages), max(percentages)
    y_min, y_max = min(values), max(values)
    if y_min == y_max:
        pad = abs(y_min) * 0.1 if y_min else 1.0
        y_min -= pad
        y_max += pad
    else:
        pad = (y_max - y_min) * 0.08
        y_min -= pad
        y_max += pad

    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf", "#8c564b"]

    def x_scale(p: int) -> float:
        return left + (plot_w / 2 if x_max == x_min else (p - x_min) * plot_w / (x_max - x_min))

    def y_scale(v: float) -> float:
        return top + (y_max - v) * plot_h / (y_max - y_min)

    lines: List[str] = []
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">')
    lines.append('<rect width="100%" height="100%" fill="white"/>')
    lines.append(f'<text x="{width/2}" y="28" text-anchor="middle" font-family="Arial" font-size="21" font-weight="700">{metric} vs Attack Percentage</text>')
    lines.append(f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>')
    lines.append(f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#222" stroke-width="1.5"/>')

    for i in range(5):
        value = y_min + (y_max - y_min) * i / 4
        yy = y_scale(value)
        lines.append(f'<line x1="{left}" y1="{yy:.2f}" x2="{left+plot_w}" y2="{yy:.2f}" stroke="#ddd"/>')
        lines.append(f'<text x="{left-12}" y="{yy+5:.2f}" text-anchor="end" font-family="Arial" font-size="12">{value:.4g}</text>')

    for p in percentages:
        xx = x_scale(p)
        lines.append(f'<line x1="{xx:.2f}" y1="{top+plot_h}" x2="{xx:.2f}" y2="{top+plot_h+6}" stroke="#222"/>')
        lines.append(f'<text x="{xx:.2f}" y="{top+plot_h+26}" text-anchor="middle" font-family="Arial" font-size="13">{p}</text>')

    lines.append(f'<text x="{left+plot_w/2}" y="{height-30}" text-anchor="middle" font-family="Arial" font-size="16">Attack Percentage (%)</text>')
    lines.append(f'<text x="24" y="{top+plot_h/2}" text-anchor="middle" font-family="Arial" font-size="15" transform="rotate(-90 24 {top+plot_h/2})">{metric}</text>')

    for idx, attack_type in enumerate(attack_types):
        color = colors[idx % len(colors)]
        series = sorted((r for r in results if int(r["attack_type"]) == attack_type), key=lambda r: int(r["attack_percentage"]))
        points = []
        for r in series:
            val = safe_float(r.get(metric))
            if math.isfinite(val):
                points.append((x_scale(int(r["attack_percentage"])), y_scale(val), val))
        if len(points) >= 2:
            lines.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="' + " ".join(f"{x:.2f},{y:.2f}" for x, y, _ in points) + '"/>')
        for x, y, val in points:
            lines.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4.5" fill="{color}"><title>Attack {attack_type}: {metric}={val:.6g}</title></circle>')
        legend_x = left + plot_w + 35
        legend_y = top + 25 + idx * 28
        lines.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x+26}" y2="{legend_y}" stroke="{color}" stroke-width="3"/>')
        lines.append(f'<text x="{legend_x+36}" y="{legend_y+5}" font-family="Arial" font-size="14">Attack {attack_type}</text>')

    lines.append("</svg>")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_all_plots(results: List[dict], out_dir: Path) -> None:
    plot_dir = out_dir / "plots"
    for metric in PLOT_METRICS:
        plot_metric_svg(results, metric, plot_dir / f"{metric}_vs_attack_percentage.svg")
    plot_metric_svg(results, "M5_MCC", out_dir / "mcc_vs_attack_percentage.svg")


def main() -> None:
    args = parse_args()
    attack_types = parse_csv_int_list(args.attack_types)
    percentages = parse_csv_int_list(args.percentages)
    out_dir = Path(args.out_dir)
    raw_dir = out_dir / "raw_outputs"
    outputs_dir = Path(args.outputs_dir)
    results_path = out_dir / "metrics_results.csv"

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
                metrics = collect_metrics(run_dir)
            else:
                metrics = {metric: float("nan") for metric in PLOT_METRICS}

            row = {"attack_type": attack_type, "attack_percentage": percentage, "run_dir": str(run_dir), **metrics}
            results = [r for r in results if not (int(r["attack_type"]) == attack_type and int(r["attack_percentage"]) == percentage)]
            results.append(row)
            results.sort(key=lambda r: (int(r["attack_type"]), int(r["attack_percentage"])))
            write_results_csv(results_path, results)
            write_all_plots(results, out_dir)
            print(f"      MCC={safe_float(row.get('M5_MCC')):.6g} PDR={safe_float(row.get('M1_PDR')):.6g} latency={safe_float(row.get('M2_avg_latency_ms')):.6g}ms")

    write_results_csv(results_path, results)
    write_all_plots(results, out_dir)
    print(f"Results: {results_path}")
    print(f"Plots:   {out_dir / 'plots'}")
    print(f"MCC plot: {out_dir / 'mcc_vs_attack_percentage.svg'}")


if __name__ == "__main__":
    main()
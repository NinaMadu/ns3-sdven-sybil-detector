#!/usr/bin/env python3
"""Run ns-3 simulations for FL raw-run dataset creation.

The script runs normal traffic and Sybil attack scenarios over an attack
percentage grid, then copies the generated CSV files from sybil-attack/outputs
into sybil-attack/fl/raw_runs using this layout:

  raw_runs/run_001_normal/0_p/*.csv
  raw_runs/run_001_normal/20_p/*.csv
  raw_runs/run_002_attack1/0_p/*.csv
  raw_runs/run_002_attack1/20_p/*.csv
  ...

Example:
  python3 sybil-attack/fl/scripts/run_raw_simulation_grid.py

The defaults are mobility_mode=5, simTime=200, attack percentages
0,20,40,60,80,100, and attack types 1..6.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List


DEFAULT_CSVS = [
    "communication_log.csv",
    "vehicle_neighbor_table_log.csv",
    "rsu_vehicle_table_log.csv",
    "rsu_vehicle_observation_rows_log.csv",
    "rsu_regional_awareness_log.csv",
    "controller_global_awareness_log.csv",
    "computed_detection_evidence_log.csv",
    "controller_vehicle_table_log.csv",
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


def parse_csv_ints(text: str) -> List[int]:
    values = [int(part.strip()) for part in text.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("expected at least one integer")
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the raw simulation grid needed for FL dataset creation."
    )
    parser.add_argument("--waf", default="./waf", help="Path to waf executable.")
    parser.add_argument(
        "--program",
        default="scratch/Sybil-Developing-Improved",
        help="ns-3 program name passed to waf --run.",
    )
    parser.add_argument("--sim-time", type=float, default=20.0)
    parser.add_argument("--mobility-mode", type=int, default=5)
    parser.add_argument("--controllers", type=int, default=4)
    parser.add_argument("--solution-mode", type=int, default=6)
    parser.add_argument("--sec-enabled", default="false")
    parser.add_argument("--attack-types", type=parse_csv_ints, default=parse_csv_ints("1,2,3,4,5,6"))
    parser.add_argument("--percentages", type=parse_csv_ints, default=parse_csv_ints("0,20,40,60,80,100"))
    parser.add_argument("--outputs-dir", default="sybil-attack/outputs")
    parser.add_argument("--raw-runs-dir", default="sybil-attack/fl/raw_runs")
    parser.add_argument(
        "--normal-all-percentages",
        action="store_true",
        default=True,
        help="Create normal/0_p, normal/20_p, ... folders. This is enabled by default.",
    )
    parser.add_argument(
        "--normal-only-zero",
        action="store_false",
        dest="normal_all_percentages",
        help="Only run/copy normal traffic into run_001_normal/0_p.",
    )
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--extra-args",
        default="",
        help="Extra ns-3 args, e.g. '--beaconInterval=1.0 --rsuReportInterval=1.5'.",
    )
    parser.add_argument(
        "--csv-files",
        default=",".join(DEFAULT_CSVS),
        help="Comma-separated output CSV filenames to copy.",
    )
    return parser.parse_args()


def build_ns3_command(
    args: argparse.Namespace,
    attack_type: int,
    percentage: int,
    normal: bool,
) -> List[str]:
    attack_enabled = "false" if normal or percentage == 0 else "true"

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


def csv_files_to_copy(args: argparse.Namespace) -> List[str]:
    return [name.strip() for name in args.csv_files.split(",") if name.strip()]


def copy_csv_outputs(outputs_dir: Path, run_dir: Path, csv_names: Iterable[str]) -> List[str]:
    run_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in csv_names:
        src = outputs_dir / name
        if not src.exists():
            continue
        shutil.copy2(src, run_dir / name)
        copied.append(name)
    return copied


def run_complete(run_dir: Path, required_csvs: Iterable[str]) -> bool:
    return run_dir.exists() and all((run_dir / name).exists() for name in required_csvs)


def write_manifest_row(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "scenario",
                "attack_type",
                "attack_percentage",
                "run_dir",
                "command",
                "copied_csv_count",
            ],
        )
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def main() -> None:
    args = parse_args()
    outputs_dir = Path(args.outputs_dir)
    raw_runs_dir = Path(args.raw_runs_dir)
    manifest_path = raw_runs_dir / "run_manifest.csv"
    csv_names = csv_files_to_copy(args)

    jobs = []
    normal_percentages = args.percentages if args.normal_all_percentages else [0]
    for percentage in normal_percentages:
        jobs.append(("normal", 0, percentage, raw_runs_dir / "run_001_normal" / f"{percentage}_p"))

    for attack_type in args.attack_types:
        scenario = f"attack{attack_type}"
        run_name = f"run_{attack_type + 1:03d}_{scenario}"
        for percentage in args.percentages:
            jobs.append((scenario, attack_type, percentage, raw_runs_dir / run_name / f"{percentage}_p"))

    for index, (scenario, attack_type, percentage, run_dir) in enumerate(jobs, start=1):
        normal = scenario == "normal"
        cmd = build_ns3_command(args, attack_type, percentage, normal)
        print(f"[{index}/{len(jobs)}] {scenario} {percentage}_p")
        print("  " + " ".join(cmd))
        print(f"  -> {run_dir}")

        if args.skip_existing and run_complete(run_dir, csv_names):
            print("  skip: required CSVs already exist")
            continue

        if not args.dry_run:
            subprocess.run(cmd, check=True)
            copied = copy_csv_outputs(outputs_dir, run_dir, csv_names)
            write_manifest_row(
                manifest_path,
                {
                    "scenario": scenario,
                    "attack_type": attack_type,
                    "attack_percentage": percentage,
                    "run_dir": str(run_dir),
                    "command": " ".join(cmd),
                    "copied_csv_count": len(copied),
                },
            )
        else:
            copied = []

        print(f"  copied_csvs={len(copied)}")

    print(f"Done. Manifest: {manifest_path}")


if __name__ == "__main__":
    main()

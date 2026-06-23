#!/usr/bin/env python3
"""Build a mixed FL training dataset from ns-3 simulation CSV outputs.

This script deliberately avoids topology assumptions:

* Labels come from simulation output ground truth:
  observed_real_id != observed_claimed_id.
* It does not create labels from "out of registry" ID ranges.
* It does not use suspicion_flags as labels or features.
* RSU/controller ids are read from simulation CSVs when present.  If the saved
  CSVs do not contain a usable hierarchy mapping, pass an explicit topology
  with --default-rsus and --num-controllers.  Those values are used only for FL
  grouping, not for labels or model features.

The model features are derived from vehicle_neighbor_table_log.csv, because
that file is the vehicle-side evidence produced after receiving V2V beacons.
"""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Dict, Iterable, Tuple

import pandas as pd


NEIGHBOR_LOG = "vehicle_neighbor_table_log.csv"

HIERARCHY_LOGS = [
    "rsu_vehicle_observation_rows_log.csv",
    "rsu_vehicle_table_log.csv",
    "controller_rsu_table_log.csv",
    "communication_log.csv",
]

FEATURE_COLUMNS = [
    "f0_bsm_speed_norm",
    "f1_estimated_distance_norm",
    "f2_received_beacon_count_norm",
    "f3_neighbor_table_size_norm",
    "f4_neighbor_age_norm",
    "f5_mean_beacon_interval_norm",
    "f6_heading_sin",
    "f7_heading_cos",
    "f8_report_staleness_norm",
    "f9_position_radius_norm",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a mixed FL dataset from simulation observation CSVs."
    )
    parser.add_argument("--raw-runs", required=True, help="Folder containing run_* subfolders.")
    parser.add_argument("--out", required=True, help="Output mixed_dataset.csv path.")
    parser.add_argument(
        "--round-duration",
        type=float,
        default=1.0,
        help="Seconds per dataset round_id bucket.",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=200_000,
        help="Rows read per chunk from each vehicle_neighbor_table_log.csv.",
    )
    parser.add_argument(
        "--default-rsus",
        type=int,
        default=0,
        help=(
            "Fallback RSU count for FL grouping when CSVs do not contain a "
            "vehicle->RSU mapping. Use the actual RSU count from the simulation."
        ),
    )
    parser.add_argument(
        "--num-controllers",
        type=int,
        default=0,
        help=(
            "Fallback controller count for FL grouping when CSVs do not contain "
            "controller mapping. Use the actual controller count from the simulation."
        ),
    )
    return parser.parse_args()


def numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default)


def clamp01(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, value))


def attack_type_from_run(run_dir: Path) -> int:
    name = run_dir.name.lower()
    if "normal" in name:
        return 0
    match = re.search(r"attack[_-]?(\d+)", name)
    if match:
        return int(match.group(1))
    return -1


def discover_runs(raw_runs: Path) -> Iterable[Path]:
    if (raw_runs / NEIGHBOR_LOG).exists():
        yield raw_runs
        return

    for child in sorted(raw_runs.iterdir()):
        if child.is_dir() and (child / NEIGHBOR_LOG).exists():
            yield child


def first_existing(columns: Iterable[str], candidates: Iterable[str]) -> str | None:
    available = set(columns)
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def read_hierarchy_maps(run_dir: Path) -> Tuple[Dict[int, int], Dict[int, int], Dict[int, int]]:
    """Read hierarchy ids from CSVs without inventing fallback topology.

    Returns:
        vehicle_to_rsu, vehicle_to_controller, rsu_to_controller
    """

    vehicle_cols = [
        "vehicle_id",
        "observer_vehicle_id",
        "observed_real_id",
        "observed_claimed_id",
        "claimed_vehicle_id",
        "real_vehicle_id",
    ]
    rsu_cols = [
        "rsu_id",
        "observer_rsu_id",
        "serving_rsu_id",
        "rsu_index",
        "source_id",
        "destination_id",
    ]
    controller_cols = [
        "controller_id",
        "observer_controller_id",
        "serving_controller_id",
        "controller_index",
    ]

    vehicle_to_rsu: Dict[int, int] = {}
    vehicle_to_controller: Dict[int, int] = {}
    rsu_to_controller: Dict[int, int] = {}

    for filename in HIERARCHY_LOGS:
        path = run_dir / filename
        if not path.exists():
            continue

        try:
            frame = pd.read_csv(path, nrows=500_000)
        except Exception:
            continue

        vehicle_col = first_existing(frame.columns, vehicle_cols)
        rsu_col = first_existing(frame.columns, rsu_cols)
        controller_col = first_existing(frame.columns, controller_cols)

        if vehicle_col and rsu_col:
            vehicles = numeric(frame[vehicle_col], -1).astype(int)
            rsus = numeric(frame[rsu_col], -1).astype(int)
            for vehicle_id, rsu_id in zip(vehicles, rsus):
                if vehicle_id >= 0 and rsu_id >= 0 and vehicle_id not in vehicle_to_rsu:
                    vehicle_to_rsu[int(vehicle_id)] = int(rsu_id)

        if vehicle_col and controller_col:
            vehicles = numeric(frame[vehicle_col], -1).astype(int)
            controllers = numeric(frame[controller_col], -1).astype(int)
            for vehicle_id, controller_id in zip(vehicles, controllers):
                if (
                    vehicle_id >= 0
                    and controller_id >= 0
                    and vehicle_id not in vehicle_to_controller
                ):
                    vehicle_to_controller[int(vehicle_id)] = int(controller_id)

        if rsu_col and controller_col:
            rsus = numeric(frame[rsu_col], -1).astype(int)
            controllers = numeric(frame[controller_col], -1).astype(int)
            for rsu_id, controller_id in zip(rsus, controllers):
                if rsu_id >= 0 and controller_id >= 0 and rsu_id not in rsu_to_controller:
                    rsu_to_controller[int(rsu_id)] = int(controller_id)

    return vehicle_to_rsu, vehicle_to_controller, rsu_to_controller


def derive_label(frame: pd.DataFrame) -> pd.Series:
    """Label rows from simulation ground truth only."""

    if {"observed_real_id", "observed_claimed_id"}.issubset(frame.columns):
        real_id = numeric(frame["observed_real_id"], -1).astype(int)
        claimed_id = numeric(frame["observed_claimed_id"], -1).astype(int)
        return ((real_id >= 0) & (claimed_id >= 0) & (real_id != claimed_id)).astype(int)

    for explicit_label in ["label", "ground_truth_label", "is_malicious", "is_attack"]:
        if explicit_label in frame.columns:
            return numeric(frame[explicit_label], 0).astype(int).clip(lower=0, upper=1)

    raise ValueError(
        "Cannot label dataset: vehicle_neighbor_table_log.csv has neither "
        "observed_real_id/observed_claimed_id nor an explicit label column."
    )


def realistic_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Build observable features from V2V neighbor-table fields."""

    index = frame.index
    time = numeric(frame.get("time", pd.Series(0, index=index)), 0.0)
    first_seen = numeric(frame.get("first_seen_time", pd.Series(0, index=index)), 0.0)
    last_seen = numeric(frame.get("last_seen_time", time), 0.0)
    speed = numeric(frame.get("bsm_speed", pd.Series(0, index=index)), 0.0)
    heading_deg = numeric(frame.get("bsm_heading", pd.Series(0, index=index)), 0.0)
    distance = numeric(frame.get("estimated_distance", pd.Series(0, index=index)), 0.0)
    beacon_count = numeric(frame.get("received_beacon_count", pd.Series(0, index=index)), 0.0)
    table_size = numeric(frame.get("neighbor_table_size", pd.Series(0, index=index)), 0.0)
    last_reported = numeric(
        frame.get("last_reported_to_rsu_time", pd.Series(-1, index=index)), -1.0
    )
    x = numeric(frame.get("bsm_x", pd.Series(0, index=index)), 0.0)
    y = numeric(frame.get("bsm_y", pd.Series(0, index=index)), 0.0)

    age = (last_seen - first_seen).clip(lower=0.0)
    mean_interval = age / beacon_count.clip(lower=1.0)
    report_staleness = (time - last_reported).where(last_reported >= 0, 30.0).clip(lower=0.0)
    heading_rad = heading_deg * math.pi / 180.0
    position_radius = (x.pow(2) + y.pow(2)).pow(0.5)

    features = pd.DataFrame(index=index)
    features["f0_bsm_speed_norm"] = (speed / 50.0).map(clamp01)
    features["f1_estimated_distance_norm"] = (distance / 300.0).map(clamp01)
    features["f2_received_beacon_count_norm"] = (beacon_count / 20.0).map(clamp01)
    features["f3_neighbor_table_size_norm"] = (table_size / 80.0).map(clamp01)
    features["f4_neighbor_age_norm"] = (age / 60.0).map(clamp01)
    features["f5_mean_beacon_interval_norm"] = (mean_interval / 5.0).map(clamp01)
    features["f6_heading_sin"] = heading_rad.map(math.sin)
    features["f7_heading_cos"] = heading_rad.map(math.cos)
    features["f8_report_staleness_norm"] = (report_staleness / 30.0).map(clamp01)
    features["f9_position_radius_norm"] = (position_radius / 5000.0).map(clamp01)
    return features


def fallback_hierarchy(
    observer_vehicle: pd.Series,
    args: argparse.Namespace,
) -> Tuple[pd.Series, pd.Series]:
    """Create deterministic FL groups only when the user gives real counts.

    This is a fallback for old/raw runs whose CSVs contain vehicle observations
    but do not log the current serving RSU/controller.  It should be called with
    the actual topology used to generate the raw runs.
    """

    if args.default_rsus <= 0 or args.num_controllers <= 0:
        missing = pd.Series(-1, index=observer_vehicle.index, dtype=int)
        return missing, missing

    rsu_id = (observer_vehicle.clip(lower=0) % args.default_rsus).astype(int)
    controller_id = (rsu_id % args.num_controllers).astype(int)
    return rsu_id, controller_id


def build_run(
    run_dir: Path,
    out_path: Path,
    write_header: bool,
    args: argparse.Namespace,
) -> Tuple[int, int, int, int, int]:
    attack_type = attack_type_from_run(run_dir)
    vehicle_to_rsu, vehicle_to_controller, rsu_to_controller = read_hierarchy_maps(run_dir)

    path = run_dir / NEIGHBOR_LOG
    total_rows = 0
    positive_rows = 0
    dropped_hierarchy_rows = 0

    for frame in pd.read_csv(path, chunksize=args.chunksize):
        if frame.empty:
            continue

        label = derive_label(frame)
        features = realistic_features(frame)

        time = numeric(frame.get("time", pd.Series(0, index=frame.index)), 0.0)
        observer_vehicle = numeric(
            frame.get("observer_vehicle_id", pd.Series(-1, index=frame.index)), -1
        ).astype(int)

        fallback_rsu, fallback_controller = fallback_hierarchy(observer_vehicle, args)

        rsu_id = observer_vehicle.map(vehicle_to_rsu).fillna(fallback_rsu).astype(int)
        controller_from_vehicle = observer_vehicle.map(vehicle_to_controller)
        controller_from_rsu = rsu_id.map(rsu_to_controller)
        controller_id = (
            controller_from_vehicle.fillna(controller_from_rsu)
            .fillna(fallback_controller)
            .astype(int)
        )

        valid_hierarchy = (rsu_id >= 0) & (controller_id >= 0)
        dropped_hierarchy_rows += int((~valid_hierarchy).sum())
        if not valid_hierarchy.any():
            continue

        frame = frame.loc[valid_hierarchy]
        label = label.loc[valid_hierarchy]
        features = features.loc[valid_hierarchy]
        time = time.loc[valid_hierarchy]
        observer_vehicle = observer_vehicle.loc[valid_hierarchy]
        rsu_id = rsu_id.loc[valid_hierarchy]
        controller_id = controller_id.loc[valid_hierarchy]

        out = pd.DataFrame(
            {
                "round_id": (time / max(args.round_duration, 1e-9)).astype(int),
                "source_run": run_dir.name,
                "attack_type": attack_type,
                "time": time,
                "vehicle_id": observer_vehicle,
                "rsu_id": rsu_id,
                "controller_id": controller_id,
                "observed_real_id": numeric(
                    frame.get("observed_real_id", pd.Series(-1, index=frame.index)), -1
                ).astype(int),
                "observed_claimed_id": numeric(
                    frame.get("observed_claimed_id", pd.Series(-1, index=frame.index)), -1
                ).astype(int),
                "label": label,
            },
            index=frame.index,
        )
        out = pd.concat([out, features], axis=1)
        out.to_csv(out_path, mode="a", header=write_header, index=False)
        write_header = False

        total_rows += len(out)
        positive_rows += int(label.sum())

    return total_rows, positive_rows, attack_type, dropped_hierarchy_rows


def main() -> None:
    args = parse_args()
    raw_runs = Path(args.raw_runs)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    runs = list(discover_runs(raw_runs))
    if not runs:
        raise SystemExit(f"No {NEIGHBOR_LOG} files found under {raw_runs}")

    write_header = True
    total_rows = 0
    total_positive = 0
    total_dropped_hierarchy = 0
    per_attack: Dict[int, Tuple[int, int]] = {}

    for run_dir in runs:
        rows, positives, attack_type, dropped_hierarchy = build_run(
            run_dir, out_path, write_header, args
        )
        write_header = False

        total_rows += rows
        total_positive += positives
        total_dropped_hierarchy += dropped_hierarchy

        old_rows, old_pos = per_attack.get(attack_type, (0, 0))
        per_attack[attack_type] = (old_rows + rows, old_pos + positives)

        print(
            f"{run_dir.name}: rows={rows} positives={positives} "
            f"positive_rate={(positives / rows if rows else 0):.6f} "
            f"dropped_missing_hierarchy={dropped_hierarchy}"
        )

    print()
    print(f"Wrote: {out_path}")
    print("Label source: observed_real_id != observed_claimed_id")
    print(f"Feature columns: {', '.join(FEATURE_COLUMNS)}")
    print(f"Total rows: {total_rows}")
    print(f"Positive labels: {total_positive}")
    print(f"Negative labels: {total_rows - total_positive}")
    print(f"Rows dropped for missing RSU/controller mapping: {total_dropped_hierarchy}")
    print("Rows by attack type:")
    for attack_type in sorted(per_attack):
        rows, positives = per_attack[attack_type]
        print(
            f"  attack {attack_type}: rows={rows} positives={positives} "
            f"positive_rate={(positives / rows if rows else 0):.6f}"
        )


if __name__ == "__main__":
    main()

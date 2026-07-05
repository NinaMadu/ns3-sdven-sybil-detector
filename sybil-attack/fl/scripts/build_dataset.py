#!/usr/bin/env python3
"""Build a mixed FL training dataset from ns-3 simulation CSV outputs.

This builder supports both the old flat raw_runs layout and the newer nested
layout produced by run_raw_simulation_grid.py:

  raw_runs/run_002_attack1/20_p/vehicle_neighbor_table_log.csv

Policy used for the current FL baseline:

* Labels come from simulation ground truth: observed_real_id != observed_claimed_id.
* Model features come from vehicle_neighbor_table_log.csv and must match the
  C++ feature extraction in scratch/fl_sybil_detection.h and
  scratch/Sybil-Developing-Improved.cc.
* FL clients are scenario-local by default: the same numeric vehicle id in two
  different simulation runs becomes two different FL client ids.
* Vehicle->RSU assignment is time-aware and derived from V2RSU/report/table
  outputs.
* RSU->controller assignment is read from output CSVs when present and falls
  back to the same static zone formula used by the simulation.
"""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pandas as pd


NEIGHBOR_LOG = "vehicle_neighbor_table_log.csv"

HIERARCHY_LOGS = [
    "rsu_vehicle_observation_rows_log.csv",
    "rsu_vehicle_table_log.csv",
    "controller_vehicle_table_log.csv",
    "controller_rsu_table_log.csv",
    "controller_global_awareness_log.csv",
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


class RunMeta(Tuple[int, int, str, int]):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a mixed FL dataset from simulation observation CSVs."
    )
    parser.add_argument("--raw-runs", required=True, help="Folder containing raw run folders.")
    parser.add_argument("--out", required=True, help="Output mixed_dataset.csv path.")
    parser.add_argument("--round-duration", type=float, default=1.0)
    parser.add_argument("--chunksize", type=int, default=200_000)
    parser.add_argument(
        "--default-rsus",
        type=int,
        default=0,
        help="Actual RSU count. Used only for fallback grouping/controller zones.",
    )
    parser.add_argument(
        "--num-controllers",
        type=int,
        default=0,
        help="Actual controller count. Used only for fallback grouping/controller zones.",
    )
    parser.add_argument(
        "--client-id-policy",
        choices=["unique_per_run", "global_vehicle_id"],
        default="unique_per_run",
        help="How to namespace FL client ids across independent simulation runs.",
    )
    parser.add_argument(
        "--run-id-stride",
        type=int,
        default=100_000,
        help="Multiplier used to create unique per-run FL client ids.",
    )
    parser.add_argument(
        "--vehicle-rsu-max-age",
        type=float,
        default=10.0,
        help="Maximum age in seconds for time-aware vehicle->RSU mapping; <=0 disables tolerance.",
    )
    return parser.parse_args()


def numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default)


def clamp01(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, value))


def attack_type_from_run(run_dir: Path) -> int:
    joined = "/".join(part.lower() for part in run_dir.parts)
    if "normal" in joined:
        return 0
    match = re.search(r"attack[_-]?(\d+)", joined)
    return int(match.group(1)) if match else -1


def attack_percentage_from_run(run_dir: Path) -> int:
    for part in reversed(run_dir.parts):
        match = re.fullmatch(r"(\d+)_p", part.lower())
        if match:
            return int(match.group(1))
    return -1


def source_run_name(raw_runs: Path, run_dir: Path) -> str:
    try:
        return str(run_dir.relative_to(raw_runs)).replace("\\", "/")
    except ValueError:
        return run_dir.name


def discover_runs(raw_runs: Path) -> Iterable[Path]:
    if (raw_runs / NEIGHBOR_LOG).exists():
        yield raw_runs
        return

    for path in sorted(raw_runs.rglob(NEIGHBOR_LOG)):
        if path.is_file():
            yield path.parent


def first_existing(columns: Iterable[str], candidates: Iterable[str]) -> str | None:
    available = set(columns)
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def fallback_controller_for_rsu(rsu_id: int, args: argparse.Namespace) -> int:
    if rsu_id < 0 or args.default_rsus <= 0 or args.num_controllers <= 0:
        return -1
    return min(args.num_controllers - 1, (rsu_id * args.num_controllers) // max(1, args.default_rsus))


def fallback_hierarchy(observer_vehicle: pd.Series, args: argparse.Namespace) -> Tuple[pd.Series, pd.Series]:
    if args.default_rsus <= 0 or args.num_controllers <= 0:
        missing = pd.Series(-1, index=observer_vehicle.index, dtype=int)
        return missing, missing

    rsu_id = (observer_vehicle.clip(lower=0) % args.default_rsus).astype(int)
    controller_id = rsu_id.map(lambda r: fallback_controller_for_rsu(int(r), args)).astype(int)
    return rsu_id, controller_id


def read_rsu_controller_map(run_dir: Path, args: argparse.Namespace) -> Dict[int, int]:
    """Read static RSU->controller mapping from logs, formula as fallback."""

    mapping: Dict[int, int] = {}

    for filename in HIERARCHY_LOGS:
        path = run_dir / filename
        if not path.exists():
            continue
        try:
            frame = pd.read_csv(path, nrows=500_000)
        except Exception:
            continue

        rsu_col = first_existing(
            frame.columns,
            ["rsu_id", "serving_rsu_id", "last_serving_rsu_id", "observer_rsu_id", "rsu_index"],
        )
        controller_col = first_existing(
            frame.columns,
            ["controller_id", "serving_controller_id", "observer_controller_id", "controller_index"],
        )
        if rsu_col and controller_col:
            rsus = numeric(frame[rsu_col], -1).astype(int)
            controllers = numeric(frame[controller_col], -1).astype(int)
            for rsu_id, controller_id in zip(rsus, controllers):
                if rsu_id >= 0 and controller_id >= 0 and rsu_id not in mapping:
                    mapping[int(rsu_id)] = int(controller_id)

    # communication_log.csv currently encodes RSU->controller reports as:
    # receiver_id = controller id, real_node_id = RSU id.
    path = run_dir / "communication_log.csv"
    if path.exists():
        try:
            for frame in pd.read_csv(path, chunksize=200_000):
                needed = {"flow", "receiver_role", "receiver_id", "real_node_id"}
                if not needed.issubset(frame.columns):
                    continue
                rows = frame[
                    (frame["flow"].astype(str) == "rsu2controller_report")
                    & (frame["receiver_role"].astype(str) == "sdn_controller")
                ]
                if rows.empty:
                    continue
                rsus = numeric(rows["real_node_id"], -1).astype(int)
                controllers = numeric(rows["receiver_id"], -1).astype(int)
                for rsu_id, controller_id in zip(rsus, controllers):
                    if rsu_id >= 0 and controller_id >= 0 and rsu_id not in mapping:
                        mapping[int(rsu_id)] = int(controller_id)
        except Exception:
            pass

    if args.default_rsus > 0 and args.num_controllers > 0:
        for rsu_id in range(args.default_rsus):
            mapping.setdefault(rsu_id, fallback_controller_for_rsu(rsu_id, args))

    return mapping


def read_vehicle_rsu_events(run_dir: Path) -> pd.DataFrame:
    """Build time-aware vehicle->RSU events from V2RSU/report/table outputs."""

    frames: List[pd.DataFrame] = []

    path = run_dir / "communication_log.csv"
    if path.exists():
        try:
            usecols = {"receive_time", "flow", "receiver_role", "receiver_id", "real_node_id"}
            for frame in pd.read_csv(path, usecols=lambda col: col in usecols, chunksize=200_000):
                if not usecols.issubset(frame.columns):
                    continue
                rows = frame[
                    (frame["flow"].astype(str) == "v2rsu_report")
                    & (frame["receiver_role"].astype(str) == "rsu_edge")
                ]
                if rows.empty:
                    continue
                frames.append(
                    pd.DataFrame(
                        {
                            "time": numeric(rows["receive_time"], -1.0),
                            "original_vehicle_id": numeric(rows["real_node_id"], -1).astype(int),
                            "rsu_id": numeric(rows["receiver_id"], -1).astype(int),
                            "hierarchy_source": "communication_v2rsu",
                        }
                    )
                )
        except Exception:
            pass

    path = run_dir / "rsu_vehicle_table_log.csv"
    if path.exists():
        try:
            frame = pd.read_csv(
                path,
                usecols=lambda col: col in {"time", "rsu_id", "real_vehicle_id", "claimed_vehicle_id"},
            )
            vehicle_col = "real_vehicle_id" if "real_vehicle_id" in frame.columns else "claimed_vehicle_id"
            if {"time", "rsu_id", vehicle_col}.issubset(frame.columns):
                frames.append(
                    pd.DataFrame(
                        {
                            "time": numeric(frame["time"], -1.0),
                            "original_vehicle_id": numeric(frame[vehicle_col], -1).astype(int),
                            "rsu_id": numeric(frame["rsu_id"], -1).astype(int),
                            "hierarchy_source": "rsu_vehicle_table",
                        }
                    )
                )
        except Exception:
            pass

    path = run_dir / "rsu_vehicle_observation_rows_log.csv"
    if path.exists():
        try:
            frame = pd.read_csv(
                path,
                usecols=lambda col: col in {"time", "rsu_id", "reported_by_vehicle_id", "row_type"},
            )
            if {"time", "rsu_id", "reported_by_vehicle_id"}.issubset(frame.columns):
                if "row_type" in frame.columns:
                    frame = frame[frame["row_type"].astype(str) == "self_report"]
                frames.append(
                    pd.DataFrame(
                        {
                            "time": numeric(frame["time"], -1.0),
                            "original_vehicle_id": numeric(frame["reported_by_vehicle_id"], -1).astype(int),
                            "rsu_id": numeric(frame["rsu_id"], -1).astype(int),
                            "hierarchy_source": "rsu_observation_self_report",
                        }
                    )
                )
        except Exception:
            pass

    if not frames:
        return pd.DataFrame(columns=["time", "original_vehicle_id", "rsu_id", "hierarchy_source"])

    events = pd.concat(frames, ignore_index=True)
    events = events[(events["time"] >= 0.0) & (events["original_vehicle_id"] >= 0) & (events["rsu_id"] >= 0)]
    events = events.drop_duplicates(["time", "original_vehicle_id", "rsu_id"])
    return events.sort_values(["time", "original_vehicle_id"]).reset_index(drop=True)


def map_vehicle_rsu_by_time(
    observer_vehicle: pd.Series,
    time: pd.Series,
    events: pd.DataFrame,
    fallback_rsu: pd.Series,
    args: argparse.Namespace,
) -> Tuple[pd.Series, pd.Series, pd.Series]:
    if events.empty:
        source = pd.Series("fallback", index=observer_vehicle.index)
        age = pd.Series(-1.0, index=observer_vehicle.index)
        return fallback_rsu.astype(int), source, age

    left = pd.DataFrame(
        {
            "_row": observer_vehicle.index,
            "original_vehicle_id": observer_vehicle.astype(int).to_numpy(),
            "time": time.astype(float).to_numpy(),
        }
    ).sort_values(["time", "original_vehicle_id"])

    right = events[["original_vehicle_id", "time", "rsu_id", "hierarchy_source"]].copy()
    right["event_time"] = right["time"]
    right = right.sort_values(["time", "original_vehicle_id"])
    tolerance = None if args.vehicle_rsu_max_age <= 0 else args.vehicle_rsu_max_age

    mapped = pd.merge_asof(
        left,
        right,
        by="original_vehicle_id",
        on="time",
        direction="backward",
        tolerance=tolerance,
    )
    mapped = mapped.set_index("_row").reindex(observer_vehicle.index)

    rsu = numeric(mapped["rsu_id"], -1).astype(int)
    missing = rsu < 0
    rsu = rsu.where(~missing, fallback_rsu.astype(int))

    source = mapped["hierarchy_source"].fillna("fallback")
    age = (time - numeric(mapped["event_time"], time)).where(~missing, -1.0)
    return rsu.astype(int), source, age.astype(float)


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
    last_reported = numeric(frame.get("last_reported_to_rsu_time", pd.Series(-1, index=index)), -1.0)
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


def make_client_id(original_vehicle: pd.Series, run_index: int, args: argparse.Namespace) -> pd.Series:
    original = original_vehicle.astype(int)
    if args.client_id_policy == "global_vehicle_id":
        return original
    return (run_index * max(1, args.run_id_stride) + original).astype(int)


def build_run(
    raw_runs: Path,
    run_dir: Path,
    run_index: int,
    out_path: Path,
    write_header: bool,
    args: argparse.Namespace,
) -> Tuple[int, int, int, int, int]:
    attack_type = attack_type_from_run(run_dir)
    attack_percentage = attack_percentage_from_run(run_dir)
    source_run = source_run_name(raw_runs, run_dir)
    vehicle_rsu_events = read_vehicle_rsu_events(run_dir)
    rsu_controller_map = read_rsu_controller_map(run_dir, args)

    path = run_dir / NEIGHBOR_LOG
    total_rows = 0
    positive_rows = 0
    dropped_hierarchy_rows = 0
    fallback_rows = 0

    for frame in pd.read_csv(path, chunksize=args.chunksize):
        if frame.empty:
            continue

        label = derive_label(frame)
        features = realistic_features(frame)
        time = numeric(frame.get("time", pd.Series(0, index=frame.index)), 0.0)
        original_vehicle = numeric(
            frame.get("observer_vehicle_id", pd.Series(-1, index=frame.index)), -1
        ).astype(int)
        vehicle_id = make_client_id(original_vehicle, run_index, args)

        fallback_rsu, fallback_controller = fallback_hierarchy(original_vehicle, args)
        rsu_id, hierarchy_source, rsu_mapping_age = map_vehicle_rsu_by_time(
            original_vehicle, time, vehicle_rsu_events, fallback_rsu, args
        )
        controller_id = rsu_id.map(lambda r: rsu_controller_map.get(int(r), fallback_controller_for_rsu(int(r), args))).astype(int)

        valid_hierarchy = (rsu_id >= 0) & (controller_id >= 0) & (original_vehicle >= 0)
        dropped_hierarchy_rows += int((~valid_hierarchy).sum())
        fallback_rows += int((hierarchy_source == "fallback").sum())
        if not valid_hierarchy.any():
            continue

        frame = frame.loc[valid_hierarchy]
        label = label.loc[valid_hierarchy]
        features = features.loc[valid_hierarchy]
        time = time.loc[valid_hierarchy]
        original_vehicle = original_vehicle.loc[valid_hierarchy]
        vehicle_id = vehicle_id.loc[valid_hierarchy]
        rsu_id = rsu_id.loc[valid_hierarchy]
        controller_id = controller_id.loc[valid_hierarchy]
        hierarchy_source = hierarchy_source.loc[valid_hierarchy]
        rsu_mapping_age = rsu_mapping_age.loc[valid_hierarchy]

        out = pd.DataFrame(
            {
                "round_id": (time / max(args.round_duration, 1e-9)).astype(int),
                "source_run": source_run,
                "run_index": run_index,
                "attack_type": attack_type,
                "attack_percentage": attack_percentage,
                "time": time,
                "vehicle_id": vehicle_id,
                "original_vehicle_id": original_vehicle,
                "rsu_id": rsu_id,
                "controller_id": controller_id,
                "hierarchy_source": hierarchy_source,
                "rsu_mapping_age_sec": rsu_mapping_age,
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

    return total_rows, positive_rows, attack_type, dropped_hierarchy_rows, fallback_rows


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
    total_fallback_rows = 0
    per_attack: Dict[int, Tuple[int, int]] = {}

    for run_index, run_dir in enumerate(runs, start=1):
        rows, positives, attack_type, dropped_hierarchy, fallback_rows = build_run(
            raw_runs, run_dir, run_index, out_path, write_header, args
        )
        if rows > 0:
            write_header = False

        total_rows += rows
        total_positive += positives
        total_dropped_hierarchy += dropped_hierarchy
        total_fallback_rows += fallback_rows

        old_rows, old_pos = per_attack.get(attack_type, (0, 0))
        per_attack[attack_type] = (old_rows + rows, old_pos + positives)

        print(
            f"{source_run_name(raw_runs, run_dir)}: rows={rows} positives={positives} "
            f"positive_rate={(positives / rows if rows else 0):.6f} "
            f"dropped_missing_hierarchy={dropped_hierarchy} fallback_hierarchy_rows={fallback_rows}"
        )

    print()
    print(f"Wrote: {out_path}")
    print("Label source: observed_real_id != observed_claimed_id")
    print(f"Client id policy: {args.client_id_policy}")
    print(f"Feature columns: {', '.join(FEATURE_COLUMNS)}")
    print(f"Total rows: {total_rows}")
    print(f"Positive labels: {total_positive}")
    print(f"Negative labels: {total_rows - total_positive}")
    print(f"Rows dropped for missing RSU/controller mapping: {total_dropped_hierarchy}")
    print(f"Rows using fallback vehicle->RSU mapping: {total_fallback_rows}")
    print("Rows by attack type:")
    for attack_type in sorted(per_attack):
        rows, positives = per_attack[attack_type]
        print(
            f"  attack {attack_type}: rows={rows} positives={positives} "
            f"positive_rate={(positives / rows if rows else 0):.6f}"
        )


if __name__ == "__main__":
    main()
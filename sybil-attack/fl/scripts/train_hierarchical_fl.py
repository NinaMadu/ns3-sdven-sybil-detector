#!/usr/bin/env python3
"""Train a hierarchical FL logistic model from mixed_dataset.csv.

Each FL round uses a time window from the dataset, recomputes fuzzy client
scores for vehicles in that window, trains selected vehicles locally, then
aggregates vehicle -> RSU -> controller -> global.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hierarchical FL trainer.")
    parser.add_argument("--dataset", required=True, help="Path to mixed_dataset.csv")
    parser.add_argument("--rounds", type=int, default=500, help="Number of FL rounds")
    parser.add_argument("--out-dir", required=True, help="Output model folder")
    parser.add_argument("--local-epochs", type=int, default=3)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument(
        "--selection-fraction",
        type=float,
        default=0.35,
        help="Fraction of candidate vehicles selected per round.",
    )
    parser.add_argument(
        "--min-selected",
        type=int,
        default=3,
        help="Minimum selected vehicles when enough candidates exist.",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=10,
        help="Dataset round_id window size used by each FL round.",
    )
    parser.add_argument(
        "--window-mode",
        choices=["sliding", "growing", "full"],
        default="sliding",
        help="How dataset round_id rows are exposed to each FL round.",
    )
    parser.add_argument(
        "--max-samples-per-client",
        type=int,
        default=2000,
        help="Cap local samples per selected vehicle per round.",
    )
    parser.add_argument("--seed", type=int, default=7)
    return parser.parse_args()


def sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(values, -40.0, 40.0)))


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    if len(y_true) == 0:
        return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "mcc": 0.0}

    pred = (y_prob >= 0.5).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())

    accuracy = (tp + tn) / max(1, len(y_true))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    denom = math.sqrt(max(1, (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    mcc = ((tp * tn) - (fp * fn)) / denom
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "mcc": mcc,
    }


def local_train(
    weights: np.ndarray,
    bias: float,
    x: np.ndarray,
    y: np.ndarray,
    local_epochs: int,
    learning_rate: float,
) -> Tuple[np.ndarray, float]:
    local_weights = weights.copy()
    local_bias = float(bias)

    if len(y) == 0:
        return local_weights, local_bias

    for _ in range(local_epochs):
        prob = sigmoid(x @ local_weights + local_bias)
        error = prob - y
        grad_w = (x.T @ error) / len(y)
        grad_b = float(error.mean())
        local_weights -= learning_rate * grad_w
        local_bias -= learning_rate * grad_b

    return local_weights, local_bias


def weighted_average(models: Iterable[Tuple[np.ndarray, float, int]]) -> Tuple[np.ndarray, float, int]:
    models = list(models)
    total = sum(count for _, _, count in models)
    if total <= 0:
        raise ValueError("Cannot average empty models")

    weights = sum(weight * count for weight, _, count in models) / total
    bias = sum(bias * count for _, bias, count in models) / total
    return weights, float(bias), total


def normalize_score(value: float, low: float, high: float) -> float:
    if high <= low:
        return 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def fuzzy_vehicle_scores(window: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    """Compute round-specific fuzzy scores for candidate vehicles."""

    rows = []
    grouped = window.groupby("vehicle_id", sort=False)
    sample_counts = grouped.size()
    max_samples = max(1, int(sample_counts.max())) if len(sample_counts) else 1
    max_round = int(window["round_id"].max()) if len(window) else 0

    for vehicle_id, group in grouped:
        n = len(group)
        if n == 0:
            continue

        positive_rate = float(group["label"].mean())
        label_balance = 1.0 - abs(0.5 - positive_rate) * 2.0
        data_amount = normalize_score(math.log1p(n), 0.0, math.log1p(max_samples))

        # Mobility/data-richness proxy from the observable feature variation.
        mobility_variation = float(group[feature_cols].std(ddof=0).fillna(0.0).mean())
        mobility_score = max(0.0, min(1.0, mobility_variation * 4.0))

        interval_quality = 1.0 - float(group["f5_mean_beacon_interval_norm"].mean())
        interval_quality = max(0.0, min(1.0, interval_quality))

        freshness = 1.0 - normalize_score(
            max_round - int(group["round_id"].max()),
            0.0,
            10.0,
        )

        fuzzy_score = (
            0.30 * data_amount
            + 0.25 * label_balance
            + 0.20 * mobility_score
            + 0.15 * interval_quality
            + 0.10 * freshness
        )

        rows.append(
            {
                "vehicle_id": int(vehicle_id),
                "sample_count": int(n),
                "positive_rate": positive_rate,
                "data_amount_score": data_amount,
                "label_balance_score": label_balance,
                "mobility_score": mobility_score,
                "interval_quality_score": interval_quality,
                "freshness_score": freshness,
                "fuzzy_score": fuzzy_score,
            }
        )

    return pd.DataFrame(rows).sort_values(
        ["fuzzy_score", "sample_count"], ascending=[False, False]
    )


def round_window(dataset: pd.DataFrame, fl_round: int, args: argparse.Namespace) -> pd.DataFrame:
    if args.window_mode == "full":
        return dataset

    available_rounds = sorted(dataset["round_id"].dropna().astype(int).unique().tolist())
    if not available_rounds:
        return dataset.iloc[0:0]

    round_index = (fl_round - 1) % len(available_rounds)
    current_round_id = available_rounds[round_index]

    if args.window_mode == "growing":
        return dataset[dataset["round_id"] <= current_round_id]

    start_round_id = current_round_id - max(1, args.window_size) + 1
    return dataset[
        (dataset["round_id"] >= start_round_id)
        & (dataset["round_id"] <= current_round_id)
    ]


def select_vehicles(scores: pd.DataFrame, args: argparse.Namespace) -> List[int]:
    if scores.empty:
        return []
    selected_count = max(args.min_selected, int(math.ceil(len(scores) * args.selection_fraction)))
    selected_count = min(selected_count, len(scores))
    return scores.head(selected_count)["vehicle_id"].astype(int).tolist()


def save_cpp_snippet(path: Path, feature_cols: List[str], weights: np.ndarray, bias: float) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("// Generated by sybil-attack/fl/scripts/train_hierarchical_fl.py\n")
        handle.write("// Feature order:\n")
        for idx, col in enumerate(feature_cols):
            handle.write(f"//   {idx}: {col}\n")
        handle.write("static const double kWeights[kNumFeatures] = {\n")
        for idx, value in enumerate(weights):
            comma = "," if idx + 1 < len(weights) else ""
            handle.write(f"    {value:.12g}{comma}\n")
        handle.write("};\n\n")
        handle.write(f"static const double kBias = {bias:.12g};\n")


def main() -> None:
    args = parse_args()
    rng = np.random.default_rng(args.seed)

    dataset = pd.read_csv(args.dataset)
    feature_cols = [col for col in dataset.columns if col.startswith("f")]
    if not feature_cols:
        raise SystemExit("No feature columns found. Expected columns beginning with 'f'.")

    required = {"round_id", "vehicle_id", "rsu_id", "controller_id", "label"}
    missing = sorted(required - set(dataset.columns))
    if missing:
        raise SystemExit(f"Dataset missing required columns: {missing}")

    dataset = dataset.dropna(subset=feature_cols + ["label", "vehicle_id", "rsu_id", "controller_id"])
    dataset = dataset[(dataset["rsu_id"] >= 0) & (dataset["controller_id"] >= 0)].copy()
    if dataset.empty:
        raise SystemExit("Dataset is empty after filtering valid hierarchy rows.")

    dataset[feature_cols] = dataset[feature_cols].astype(float)
    dataset["label"] = dataset["label"].astype(int)
    dataset["round_id"] = dataset["round_id"].astype(int)
    dataset["vehicle_id"] = dataset["vehicle_id"].astype(int)
    dataset["rsu_id"] = dataset["rsu_id"].astype(int)
    dataset["controller_id"] = dataset["controller_id"].astype(int)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    weights = np.zeros(len(feature_cols), dtype=float)
    bias = 0.0
    history_rows = []
    selection_rows = []

    for fl_round in range(1, args.rounds + 1):
        window = round_window(dataset, fl_round, args)
        scores = fuzzy_vehicle_scores(window, feature_cols)
        selected_vehicles = select_vehicles(scores, args)

        if not selected_vehicles:
            history_rows.append(
                {
                    "fl_round": fl_round,
                    "window_rows": len(window),
                    "selected_vehicles": 0,
                    "trained_samples": 0,
                    "accuracy": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "mcc": 0.0,
                }
            )
            continue

        selected_set = set(selected_vehicles)
        selected_scores = scores[scores["vehicle_id"].isin(selected_set)].copy()
        selected_scores.insert(0, "fl_round", fl_round)
        selection_rows.extend(selected_scores.to_dict("records"))

        vehicle_models: Dict[int, Tuple[np.ndarray, float, int, int, int]] = {}
        for vehicle_id, group in window[window["vehicle_id"].isin(selected_set)].groupby("vehicle_id"):
            if len(group) > args.max_samples_per_client:
                group = group.sample(args.max_samples_per_client, random_state=int(rng.integers(0, 2**31 - 1)))

            x = group[feature_cols].to_numpy(dtype=float)
            y = group["label"].to_numpy(dtype=float)
            local_weights, local_bias = local_train(
                weights,
                bias,
                x,
                y,
                args.local_epochs,
                args.learning_rate,
            )
            rsu_id = int(group["rsu_id"].mode().iloc[0])
            controller_id = int(group["controller_id"].mode().iloc[0])
            vehicle_models[int(vehicle_id)] = (
                local_weights,
                local_bias,
                len(group),
                rsu_id,
                controller_id,
            )

        rsu_models: Dict[int, Tuple[np.ndarray, float, int, int]] = {}
        for rsu_id in sorted({model[3] for model in vehicle_models.values()}):
            members = [
                (model[0], model[1], model[2])
                for model in vehicle_models.values()
                if model[3] == rsu_id
            ]
            rsu_weights, rsu_bias, rsu_count = weighted_average(members)
            controller_ids = [
                model[4] for model in vehicle_models.values() if model[3] == rsu_id
            ]
            controller_id = max(set(controller_ids), key=controller_ids.count)
            rsu_models[rsu_id] = (rsu_weights, rsu_bias, rsu_count, int(controller_id))

        controller_models: Dict[int, Tuple[np.ndarray, float, int]] = {}
        for controller_id in sorted({model[3] for model in rsu_models.values()}):
            members = [
                (model[0], model[1], model[2])
                for model in rsu_models.values()
                if model[3] == controller_id
            ]
            controller_models[controller_id] = weighted_average(members)

        weights, bias, trained_samples = weighted_average(controller_models.values())

        eval_x = window[feature_cols].to_numpy(dtype=float)
        eval_y = window["label"].to_numpy(dtype=int)
        metrics = binary_metrics(eval_y, sigmoid(eval_x @ weights + bias))
        history_rows.append(
            {
                "fl_round": fl_round,
                "window_rows": len(window),
                "selected_vehicles": len(selected_vehicles),
                "trained_samples": trained_samples,
                **metrics,
            }
        )

        if fl_round == 1 or fl_round % 25 == 0 or fl_round == args.rounds:
            print(
                f"round={fl_round} window_rows={len(window)} "
                f"selected={len(selected_vehicles)} trained={trained_samples} "
                f"mcc={metrics['mcc']:.4f}"
            )

    final_weights = {
        "feature_columns": feature_cols,
        "weights": weights.tolist(),
        "bias": bias,
        "rounds": args.rounds,
        "window_mode": args.window_mode,
        "window_size": args.window_size,
    }

    final_weights_path = out_dir / "final_weights.json"
    snippet_path = out_dir / "fl_sybil_detection_weights_snippet.h"
    history_path = out_dir / "training_history.csv"
    selection_path = out_dir / "selected_vehicles_by_round.csv"

    final_weights_path.write_text(json.dumps(final_weights, indent=2), encoding="utf-8")
    save_cpp_snippet(snippet_path, feature_cols, weights, bias)

    with history_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(history_rows[0].keys()))
        writer.writeheader()
        writer.writerows(history_rows)

    if selection_rows:
        with selection_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(selection_rows[0].keys()))
            writer.writeheader()
            writer.writerows(selection_rows)

    print()
    print(f"Final weights: {final_weights_path}")
    print(f"C++ snippet:   {snippet_path}")
    print(f"History:       {history_path}")
    print(f"Selections:    {selection_path}")


if __name__ == "__main__":
    main()

"""
run_experiment.py — End-to-end FLEMDS experiment runner.

Usage
-----
# Step 1: generate the dataset (from ns-3.35 build directory)
#   cd ns-allinone-3.35/ns-3.35
#   ./waf --run 'Sybil-Developing-Improved \\
#       --config=sybil-attack/configs/sybil_fl_detection.cfg'
#
# Step 2: run this script from python_fl/
#   python run_experiment.py [--dataset PATH] [--rounds N] [--seq_len T]

Default dataset path: ../sybil-attack/outputs/fl_dataset.csv
(relative to the python_fl/ directory, matching the ns-3 output location)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Dict

import numpy as np
import torch

# Ensure local modules are importable
sys.path.insert(0, os.path.dirname(__file__))

from data_prep import (
    load_dataset,
    print_class_distribution,
    fit_scaler,
    apply_scaler,
    build_all_sequences,
    get_flbflvs_metrics,
    assign_vehicles_to_rsus,
    train_val_split,
    FEATURE_COLS,
    TARGET_COL,
    VEHICLE_ID_COL,
)
from fuzzy_selector import FLBFLVSSelector
from local_model import SybilLSTM, DEFAULT_N_FEATURES, get_parameters, set_parameters
from fl_client import VehicleFlClient, build_clients
from fl_server import run_hierarchical_fl
from evaluate import evaluate_global_model, plot_results

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_DATASET = os.path.join(
    os.path.dirname(__file__),
    "..", "outputs", "fl_dataset.csv",
)

# RSU x-positions from sybil_fl_detection.cfg: 3 RSUs along an 800m road
RSU_X_POSITIONS = [133.0, 400.0, 667.0]


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="FLEMDS hierarchical federated learning experiment"
    )
    p.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help="Path to fl_dataset.csv produced by ns-3",
    )
    p.add_argument("--rounds",      type=int,   default=10,
                   help="Number of global FL rounds")
    p.add_argument("--seq_len",     type=int,   default=10,
                   help="LSTM input sequence length (seconds)")
    p.add_argument("--fraction",    type=float, default=0.7,
                   help="FLBFLVS client selection fraction per round")
    p.add_argument("--min_clients", type=int,   default=2,
                   help="Minimum clients required per FL round")
    p.add_argument("--val_frac",    type=float, default=0.2,
                   help="Fraction of each vehicle's data held out for validation")
    p.add_argument("--output_dir",  default="results",
                   help="Directory to save plots and model")
    p.add_argument("--device",      default="cpu",
                   help="PyTorch device (cpu or cuda)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load and inspect dataset
    # ------------------------------------------------------------------
    log.info("Loading dataset: %s", args.dataset)
    df = load_dataset(args.dataset)
    print_class_distribution(df)

    # ------------------------------------------------------------------
    # 2. Normalise features
    # ------------------------------------------------------------------
    log.info("Fitting feature scaler on full dataset")
    scaler = fit_scaler(df)
    df_norm = apply_scaler(df, scaler)

    # ------------------------------------------------------------------
    # 3. Build time-series sequences per vehicle
    # ------------------------------------------------------------------
    log.info("Building LSTM sequences (seq_len=%d)", args.seq_len)
    all_seqs, vehicle_ids = build_all_sequences(df_norm, seq_len=args.seq_len)

    if len(vehicle_ids) == 0:
        log.error("No vehicles with data found in dataset. Exiting.")
        sys.exit(1)

    log.info("Vehicles with sequences: %d", len(vehicle_ids))

    # ------------------------------------------------------------------
    # 4. Train / validation split
    # ------------------------------------------------------------------
    train_seqs, val_seqs = train_val_split(all_seqs, val_fraction=args.val_frac)

    # ------------------------------------------------------------------
    # 5. Assign vehicles to RSU zones
    # ------------------------------------------------------------------
    rsu_zones = assign_vehicles_to_rsus(df, rsu_x_positions=RSU_X_POSITIONS)
    log.info("RSU zone assignment: %s", rsu_zones)

    # ------------------------------------------------------------------
    # 6. FLBFLVS: score all vehicles and report selection
    # ------------------------------------------------------------------
    flbflvs_metrics = get_flbflvs_metrics(df_norm)
    selector = FLBFLVSSelector()
    scores = selector.score_all(flbflvs_metrics)
    log.info(
        "FLBFLVS scores — min %.3f  max %.3f  mean %.3f",
        min(scores.values()), max(scores.values()),
        sum(scores.values()) / len(scores),
    )

    # ------------------------------------------------------------------
    # 7. Build Flower clients
    # ------------------------------------------------------------------
    clients = build_clients(
        train_seqs      = train_seqs,
        val_seqs        = val_seqs,
        flbflvs_metrics = flbflvs_metrics,
        device          = args.device,
    )

    # Flower simulation requires a client_fn(cid: str) -> Client
    def client_fn(cid: str) -> fl.client.Client:
        vid = int(cid)
        if vid not in clients:
            # Fallback: create a fresh client with empty data if unknown ID
            dummy = np.zeros((1, args.seq_len, DEFAULT_N_FEATURES), dtype=np.float32)
            dummy_y = np.zeros(1, dtype=np.int32)
            return VehicleFlClient(
                vehicle_id=vid, X_train=dummy, y_train=dummy_y,
                X_val=dummy, y_val=dummy_y, device=args.device,
            ).to_client()
        return clients[vid].to_client()

    # ------------------------------------------------------------------
    # 8. Run 3-tier hierarchical FL simulation
    # ------------------------------------------------------------------
    log.info(
        "Starting FLEMDS FL simulation: %d rounds, %d vehicles, "
        "selection_fraction=%.1f",
        args.rounds, len(vehicle_ids), args.fraction,
    )
    import flwr as fl
    history, strategy = run_hierarchical_fl(
        client_fn          = client_fn,
        vehicle_ids        = vehicle_ids,
        rsu_zones          = rsu_zones,
        vehicle_metrics    = flbflvs_metrics,
        num_rounds         = args.rounds,
        selection_fraction = args.fraction,
        min_fit_clients    = args.min_clients,
    )

    # ------------------------------------------------------------------
    # 9. Save final global model
    # ------------------------------------------------------------------
    # Retrieve final parameters from history (last distributed parameters)
    model_path = os.path.join(args.output_dir, "flemds_global_model.pt")
    final_model = SybilLSTM()
    # The server distributes parameters after each round; use any client
    # that participated in the last round to recover the final weights.
    if clients:
        first_client = next(iter(clients.values()))
        final_params = first_client.get_parameters({})
        set_parameters(final_model, final_params)
        torch.save(final_model.state_dict(), model_path)
        log.info("Final model saved to %s", model_path)

    # ------------------------------------------------------------------
    # 10. Evaluate and plot
    # ------------------------------------------------------------------
    # Aggregate all validation sequences for global evaluation
    X_val_all = np.concatenate(
        [val_seqs[v][0] for v in vehicle_ids if v in val_seqs], axis=0
    )
    y_val_all = np.concatenate(
        [val_seqs[v][1] for v in vehicle_ids if v in val_seqs], axis=0
    )

    log.info("Evaluating global model on %d validation samples", len(y_val_all))
    metrics = evaluate_global_model(final_model, X_val_all, y_val_all,
                                    device=args.device)

    print("\n=== FLEMDS Global Model Evaluation ===")
    for k, v in metrics.items():
        print(f"  {k:25s}: {v:.4f}")

    plot_results(
        history    = history,
        metrics    = metrics,
        scores     = scores,
        output_dir = args.output_dir,
    )

    log.info("Results saved to %s/", args.output_dir)


if __name__ == "__main__":
    main()

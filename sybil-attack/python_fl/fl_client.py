"""
fl_client.py — Flower NumPyClient for a single vehicle (FLEMDS Tier-1).

Each vehicle trains a local SybilLSTM on its own BSM time-series and
exchanges parameters with the aggregating server (RSU or global).

The client also exposes the latest FLBFLVS resource metrics so the server
can perform fuzzy-based client selection in `configure_fit`.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
import flwr as fl

from local_model import (
    SybilLSTM,
    DEFAULT_N_FEATURES,
    DEFAULT_HIDDEN_SIZE,
    DEFAULT_N_LAYERS,
    DEFAULT_DROPOUT,
    DEFAULT_LOCAL_EPOCHS,
    DEFAULT_LR,
    DEFAULT_BATCH_SIZE,
    get_parameters,
    set_parameters,
    local_train,
    local_evaluate,
    compute_pos_weight,
)


class VehicleFlClient(fl.client.NumPyClient):
    """
    On-vehicle Flower client (FLEMDS Tier-1).

    Parameters
    ----------
    vehicle_id      : ns-3 node index
    X_train, y_train: training sequences from data_prep.make_sequences
    X_val,   y_val  : validation sequences
    flbflvs_metrics : latest {rssi_avg_dbm, residual_energy_pct,
                               memory_free_pct, data_quality} snapshot
    device          : "cpu" or "cuda"
    """

    def __init__(
        self,
        vehicle_id:      int,
        X_train:         np.ndarray,
        y_train:         np.ndarray,
        X_val:           np.ndarray,
        y_val:           np.ndarray,
        flbflvs_metrics: Dict[str, float] | None = None,
        device:          str = "cpu",
    ) -> None:
        self.vehicle_id      = vehicle_id
        self.X_train         = X_train
        self.y_train         = y_train
        self.X_val           = X_val
        self.y_val           = y_val
        self.flbflvs_metrics = flbflvs_metrics or {}
        self.device          = device

        self.model = SybilLSTM(
            n_features  = DEFAULT_N_FEATURES,
            hidden_size = DEFAULT_HIDDEN_SIZE,
            n_layers    = DEFAULT_N_LAYERS,
            dropout     = DEFAULT_DROPOUT,
        )

    # ------------------------------------------------------------------
    # Flower NumPyClient interface
    # ------------------------------------------------------------------

    def get_parameters(self, config: Dict) -> List[np.ndarray]:
        return get_parameters(self.model)

    def fit(
        self,
        parameters: List[np.ndarray],
        config: Dict,
    ) -> Tuple[List[np.ndarray], int, Dict]:
        set_parameters(self.model, parameters)

        epochs     = int(config.get("local_epochs", DEFAULT_LOCAL_EPOCHS))
        lr         = float(config.get("lr", DEFAULT_LR))
        batch_size = int(config.get("batch_size", DEFAULT_BATCH_SIZE))

        pos_weight = compute_pos_weight(self.y_train)
        loss = local_train(
            self.model,
            self.X_train, self.y_train,
            epochs=epochs, lr=lr, batch_size=batch_size,
            pos_weight=pos_weight, device=self.device,
        )

        metrics = {
            "vehicle_id": self.vehicle_id,
            "train_loss": loss,
            "n_train":    len(self.y_train),
            # Pass FLBFLVS metrics so the server can log them
            **{f"flbflvs_{k}": v for k, v in self.flbflvs_metrics.items()},
        }
        return get_parameters(self.model), len(self.y_train), metrics

    def evaluate(
        self,
        parameters: List[np.ndarray],
        config: Dict,
    ) -> Tuple[float, int, Dict]:
        set_parameters(self.model, parameters)
        loss, acc = local_evaluate(
            self.model, self.X_val, self.y_val,
            device=self.device,
        )
        return loss, len(self.y_val), {"accuracy": acc, "vehicle_id": self.vehicle_id}


# ---------------------------------------------------------------------------
# Factory: build all clients from pre-split sequence dicts
# ---------------------------------------------------------------------------

def build_clients(
    train_seqs: Dict[int, Tuple[np.ndarray, np.ndarray]],
    val_seqs:   Dict[int, Tuple[np.ndarray, np.ndarray]],
    flbflvs_metrics: Dict[int, Dict[str, float]] | None = None,
    device: str = "cpu",
) -> Dict[int, VehicleFlClient]:
    """
    Instantiate one VehicleFlClient per vehicle ID in train_seqs.

    Parameters
    ----------
    train_seqs       : {vid: (X_train, y_train)}
    val_seqs         : {vid: (X_val,   y_val)}
    flbflvs_metrics  : {vid: {rssi_avg_dbm, residual_energy_pct,
                               memory_free_pct, data_quality}}
    """
    metrics = flbflvs_metrics or {}
    clients: Dict[int, VehicleFlClient] = {}
    for vid, (X_tr, y_tr) in train_seqs.items():
        X_v, y_v = val_seqs.get(vid, (X_tr[-1:], y_tr[-1:]))
        clients[vid] = VehicleFlClient(
            vehicle_id      = vid,
            X_train         = X_tr,
            y_train         = y_tr,
            X_val           = X_v,
            y_val           = y_v,
            flbflvs_metrics = metrics.get(vid, {}),
            device          = device,
        )
    return clients

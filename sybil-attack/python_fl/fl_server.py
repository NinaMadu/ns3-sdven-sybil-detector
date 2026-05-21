"""
fl_server.py — FLEMDS 3-tier hierarchical Federated Learning server.

Architecture (FLEMDS paper §IV-B):
    Tier 1 — On-vehicle local training          (VehicleFlClient)
    Tier 2 — RSU-level FedAvg aggregation       (per RSU zone)
    Tier 3 — Global FedAvg aggregation           (across all RSU models)

This is implemented as a single Flower strategy
(HierarchicalFedAvg extends FedAvg) that overrides `aggregate_fit` to
perform the two-level averaging, and overrides `configure_fit` to perform
FLBFLVS-based client selection before each global round.

The three-tier flow per global round r:
    1. FLBFLVS selects a subset S ⊆ all vehicles.
    2. Each v ∈ S trains locally (Tier 1).
    3. Server groups S by RSU zone, FedAvg within each zone (Tier 2).
    4. Server FedAvg across the RSU-zone aggregated models (Tier 3).
    5. Broadcast global model to all clients.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import flwr as fl
from flwr.common import (
    FitIns,
    FitRes,
    Parameters,
    Scalar,
    ndarrays_to_parameters,
    parameters_to_ndarrays,
)
from flwr.server.client_proxy import ClientProxy
from flwr.server.strategy import FedAvg
from flwr.server.strategy.aggregate import aggregate

from fuzzy_selector import FLBFLVSSelector

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Weighted FedAvg helpers (operate on List[np.ndarray])
# ---------------------------------------------------------------------------

def _weighted_average(
    updates: List[Tuple[List[np.ndarray], int]],
) -> List[np.ndarray]:
    """
    Perform FedAvg: weighted average of model parameter lists.

    Parameters
    ----------
    updates : [(params, n_examples), ...]

    Returns
    -------
    averaged parameter list
    """
    total = sum(n for _, n in updates)
    if total == 0:
        return updates[0][0]
    avg = [
        np.sum([params[i] * (n / total) for params, n in updates], axis=0)
        for i in range(len(updates[0][0]))
    ]
    return avg


# ---------------------------------------------------------------------------
# HierarchicalFedAvg strategy
# ---------------------------------------------------------------------------

class HierarchicalFedAvg(FedAvg):
    """
    Custom Flower strategy implementing the FLEMDS 3-tier hierarchy.

    Parameters
    ----------
    rsu_zones          : {vehicle_id: rsu_id}
    vehicle_metrics    : {vehicle_id: {rssi_avg_dbm, residual_energy_pct,
                                        memory_free_pct, data_quality}}
    selection_fraction : fraction of vehicles selected per round via FLBFLVS
    min_fit_clients    : absolute minimum clients required per round
    All other kwargs   : forwarded to FedAvg (e.g. evaluate_fn)
    """

    def __init__(
        self,
        rsu_zones:          Dict[int, int],
        vehicle_metrics:    Dict[int, Dict[str, float]],
        selection_fraction: float = 0.7,
        min_fit_clients:    int   = 2,
        **kwargs,
    ) -> None:
        # FedAvg needs fraction_fit; we set it to 1.0 and do our own selection
        super().__init__(
            fraction_fit     = 1.0,
            fraction_evaluate= 1.0,
            min_fit_clients  = min_fit_clients,
            **kwargs,
        )
        self.rsu_zones          = rsu_zones          # {vid: rsu_id}
        self.vehicle_metrics    = vehicle_metrics    # {vid: metric_dict}
        self.selection_fraction = selection_fraction
        self.min_fit_clients    = min_fit_clients
        self.fuzzy_selector     = FLBFLVSSelector()

        # Round-level history for logging
        self._round_history: List[Dict] = []

    # ------------------------------------------------------------------
    # Tier-1+2+3: aggregation
    # ------------------------------------------------------------------

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        if not results:
            return None, {}

        # ── Tier 2: group clients by RSU zone ──────────────────────────
        rsu_groups: Dict[int, List[Tuple[List[np.ndarray], int]]] = defaultdict(list)
        for client_proxy, fit_res in results:
            vid    = int(client_proxy.cid)
            rsu_id = self.rsu_zones.get(vid, 0)
            params = parameters_to_ndarrays(fit_res.parameters)
            rsu_groups[rsu_id].append((params, fit_res.num_examples))

        log.info(
            "[Round %d] Tier-2: aggregating %d RSU zones (%d clients total)",
            server_round, len(rsu_groups), len(results),
        )

        # RSU-level FedAvg within each zone
        rsu_aggregated: List[Tuple[List[np.ndarray], int]] = []
        for rsu_id, zone_updates in rsu_groups.items():
            rsu_params = _weighted_average(zone_updates)
            rsu_total  = sum(n for _, n in zone_updates)
            rsu_aggregated.append((rsu_params, rsu_total))
            log.debug(
                "  RSU %d: %d clients, %d samples",
                rsu_id, len(zone_updates), rsu_total,
            )

        # ── Tier 3: global FedAvg across RSU models ───────────────────
        global_params = _weighted_average(rsu_aggregated)
        global_total  = sum(n for _, n in rsu_aggregated)

        log.info(
            "[Round %d] Tier-3: global aggregation over %d RSU models, %d total samples",
            server_round, len(rsu_aggregated), global_total,
        )

        # Record round history
        self._round_history.append({
            "round":       server_round,
            "n_clients":   len(results),
            "n_rsu_zones": len(rsu_groups),
            "total_samples": global_total,
        })

        return ndarrays_to_parameters(global_params), {}

    # ------------------------------------------------------------------
    # FLBFLVS client selection (overrides FedAvg.configure_fit)
    # ------------------------------------------------------------------

    def configure_fit(
        self,
        server_round: int,
        parameters: Parameters,
        client_manager: fl.server.ClientManager,
    ) -> List[Tuple[ClientProxy, FitIns]]:
        """Select clients using FLBFLVS fuzzy scoring before each round."""

        # Wait until we have enough clients
        client_manager.wait_for(self.min_fit_clients, timeout=30)
        all_clients = client_manager.all()

        if not all_clients:
            return []

        # Score available clients
        available_metrics = {
            int(cid): self.vehicle_metrics.get(int(cid), {})
            for cid in all_clients
        }
        k = max(self.min_fit_clients,
                int(len(all_clients) * self.selection_fraction))
        selected_ids = self.fuzzy_selector.select_top_k(available_metrics, k)

        log.info(
            "[Round %d] FLBFLVS selected %d / %d clients",
            server_round, len(selected_ids), len(all_clients),
        )

        # Attach training config
        config = {
            "server_round": server_round,
            "local_epochs": 3,
            "lr":           1e-3,
            "batch_size":   32,
        }
        fit_ins = FitIns(parameters, config)

        selected_set = set(str(v) for v in selected_ids)
        return [
            (proxy, fit_ins)
            for cid, proxy in all_clients.items()
            if cid in selected_set
        ]

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def round_history(self) -> List[Dict]:
        return list(self._round_history)


# ---------------------------------------------------------------------------
# Simulation entry point
# ---------------------------------------------------------------------------

def run_hierarchical_fl(
    client_fn:         Callable[[str], fl.client.Client],
    vehicle_ids:       List[int],
    rsu_zones:         Dict[int, int],
    vehicle_metrics:   Dict[int, Dict[str, float]],
    num_rounds:        int = 10,
    selection_fraction: float = 0.7,
    min_fit_clients:   int = 2,
) -> Tuple[fl.server.History, HierarchicalFedAvg]:
    """
    Run the complete FLEMDS 3-tier FL simulation in-process.

    Parameters
    ----------
    client_fn           : Flower client factory  fn(cid: str) → Client
    vehicle_ids         : list of vehicle IDs (used as client IDs)
    rsu_zones           : {vehicle_id: rsu_id}
    vehicle_metrics     : {vehicle_id: FLBFLVS metric dict}
    num_rounds          : global FL rounds
    selection_fraction  : fraction of clients selected per round
    min_fit_clients     : minimum clients required per round

    Returns
    -------
    (history, strategy)
    """
    strategy = HierarchicalFedAvg(
        rsu_zones          = rsu_zones,
        vehicle_metrics    = vehicle_metrics,
        selection_fraction = selection_fraction,
        min_fit_clients    = min_fit_clients,
    )

    history = fl.simulation.start_simulation(
        client_fn    = client_fn,
        num_clients  = len(vehicle_ids),
        client_resources = {"num_cpus": 1},
        config       = fl.server.ServerConfig(num_rounds=num_rounds),
        strategy     = strategy,
    )

    return history, strategy

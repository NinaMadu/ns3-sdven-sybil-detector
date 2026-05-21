"""
fuzzy_selector.py — FLBFLVS: Fuzzy Logic Based FL Vehicle Selection.

Implements the client-selection mechanism from the FLEMDS paper (§IV-A).

Four antecedents (all in [0,1] after normalisation):
    rssi_quality       — signal strength (0 = very weak, 1 = strong)
    energy_pct         — residual battery (0–100 %)
    memory_free_pct    — available memory  (0–100 %)
    data_quality       — beacon delivery / freshness (0–1)

One consequent:
    selection_score    — FL participation priority (0–1)

Rule base: all 3^4 = 81 input-level combinations are covered
programmatically using a weighted-minimum quality heuristic that matches
the priority ordering stated in the FLEMDS paper.

Inference engine : Mamdani
Defuzzification  : centroid method (skfuzzy default)
"""

from __future__ import annotations

from itertools import product as iproduct
from typing import Dict, List, Tuple

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl


# ---------------------------------------------------------------------------
# Membership function builder helpers
# ---------------------------------------------------------------------------

def _trimf(universe: np.ndarray, abc: Tuple[float, float, float]) -> np.ndarray:
    return fuzz.trimf(universe, list(abc))


def _trapmf(universe: np.ndarray,
            abcd: Tuple[float, float, float, float]) -> np.ndarray:
    return fuzz.trapmf(universe, list(abcd))


# ---------------------------------------------------------------------------
# Quality-level enumeration (used in the programmatic rule table)
# ---------------------------------------------------------------------------
_L, _M, _H = 0, 1, 2
_LEVEL_NAMES = {_L: "low", _M: "medium", _H: "high"}


def _output_level(r: int, e: int, m: int, d: int) -> int:
    """
    Map four input quality levels to an output selection score level.

    Logic (matches FLEMDS paper §IV-A priority ordering):
      - Energy or memory = Low  →  Low score (insufficient resources for FL)
      - All four = High          →  High score
      - Avg quality ≥ 1.5        →  High score
      - Avg quality ≥ 0.75       →  Medium score
      - Otherwise                →  Low score
    """
    if e == _L or m == _L:
        return _L
    avg = (r + e + m + d) / 4.0
    if avg >= 1.5:
        return _H
    if avg >= 0.75:
        return _M
    return _L


# ---------------------------------------------------------------------------
# FLBFLVSSelector
# ---------------------------------------------------------------------------

class FLBFLVSSelector:
    """
    Fuzzy Logic Based FL Vehicle Selection (FLBFLVS).

    Usage
    -----
    selector = FLBFLVSSelector()
    score = selector.score(rssi_dbm=-70, energy_pct=80,
                           memory_free_pct=90, data_quality=0.9)
    selected_ids = selector.select_top_k(vehicle_metrics, k=5)
    """

    # RSSI normalisation range (dBm → [0,1])
    RSSI_MIN = -100.0
    RSSI_MAX = -40.0

    def __init__(self) -> None:
        self._build_fuzzy_system()

    # ------------------------------------------------------------------
    def _build_fuzzy_system(self) -> None:
        """Construct the Mamdani control system with all 81 rules."""

        # ── Universes ──────────────────────────────────────────────────
        u_01  = np.arange(0.0, 1.01, 0.01)   # normalised [0,1]
        u_pct = np.arange(0.0, 101.0, 1.0)   # percent [0,100]

        # ── Antecedents ────────────────────────────────────────────────
        rssi  = ctrl.Antecedent(u_01,  "rssi_quality")
        energy = ctrl.Antecedent(u_pct, "energy_pct")
        memory = ctrl.Antecedent(u_pct, "memory_free_pct")
        dq     = ctrl.Antecedent(u_01,  "data_quality")

        # ── Consequent ─────────────────────────────────────────────────
        score  = ctrl.Consequent(u_01, "selection_score", defuzzify_method="centroid")

        # ── Membership functions (triangular / trapezoidal) ────────────
        # RSSI quality
        rssi["low"]    = _trapmf(u_01, (0.0, 0.0, 0.25, 0.5))
        rssi["medium"] = _trimf(u_01,  (0.25, 0.5, 0.75))
        rssi["high"]   = _trapmf(u_01, (0.5, 0.75, 1.0, 1.0))

        # Energy (%)
        energy["low"]    = _trapmf(u_pct, (0, 0, 20, 40))
        energy["medium"] = _trimf(u_pct,  (20, 50, 80))
        energy["high"]   = _trapmf(u_pct, (60, 80, 100, 100))

        # Memory free (%)
        memory["low"]    = _trapmf(u_pct, (0, 0, 20, 40))
        memory["medium"] = _trimf(u_pct,  (20, 50, 80))
        memory["high"]   = _trapmf(u_pct, (60, 80, 100, 100))

        # Data quality
        dq["low"]    = _trapmf(u_01, (0.0, 0.0, 0.25, 0.5))
        dq["medium"] = _trimf(u_01,  (0.25, 0.5, 0.75))
        dq["high"]   = _trapmf(u_01, (0.5, 0.75, 1.0, 1.0))

        # Selection score
        score["low"]    = _trapmf(u_01, (0.0, 0.0, 0.25, 0.5))
        score["medium"] = _trimf(u_01,  (0.25, 0.5, 0.75))
        score["high"]   = _trapmf(u_01, (0.5, 0.75, 1.0, 1.0))

        # ── All 81 rules generated programmatically ────────────────────
        antecedents = [rssi, energy, memory, dq]
        rules: List[ctrl.Rule] = []
        for r_l, e_l, m_l, d_l in iproduct(range(3), repeat=4):
            out_l = _output_level(r_l, e_l, m_l, d_l)
            condition = (
                antecedents[0][_LEVEL_NAMES[r_l]] &
                antecedents[1][_LEVEL_NAMES[e_l]] &
                antecedents[2][_LEVEL_NAMES[m_l]] &
                antecedents[3][_LEVEL_NAMES[d_l]]
            )
            rules.append(ctrl.Rule(condition, score[_LEVEL_NAMES[out_l]]))

        self._ctrl_sys = ctrl.ControlSystem(rules)
        self._sim      = ctrl.ControlSystemSimulation(self._ctrl_sys)

    # ------------------------------------------------------------------
    def _normalise_rssi(self, rssi_dbm: float) -> float:
        """Map dBm value to [0, 1]; clipped at the configured range."""
        return float(np.clip(
            (rssi_dbm - self.RSSI_MIN) / (self.RSSI_MAX - self.RSSI_MIN),
            0.0, 1.0
        ))

    # ------------------------------------------------------------------
    def score(
        self,
        rssi_dbm: float,
        energy_pct: float,
        memory_free_pct: float,
        data_quality: float,
    ) -> float:
        """
        Compute the FLBFLVS selection score for one vehicle.

        Parameters
        ----------
        rssi_dbm         : measured RSSI (dBm), typically -100 to -40
        energy_pct       : residual battery 0–100 %
        memory_free_pct  : free memory   0–100 %
        data_quality     : beacon delivery ratio 0–1

        Returns
        -------
        float in [0, 1]  — higher = more suitable for FL participation
        """
        self._sim.input["rssi_quality"]     = self._normalise_rssi(rssi_dbm)
        self._sim.input["energy_pct"]       = float(np.clip(energy_pct, 0, 100))
        self._sim.input["memory_free_pct"]  = float(np.clip(memory_free_pct, 0, 100))
        self._sim.input["data_quality"]     = float(np.clip(data_quality, 0, 1))
        try:
            self._sim.compute()
            return float(self._sim.output["selection_score"])
        except Exception:
            # Fallback: weighted arithmetic mean (handles degenerate inputs)
            r_n  = self._normalise_rssi(rssi_dbm)
            e_n  = np.clip(energy_pct, 0, 100) / 100.0
            m_n  = np.clip(memory_free_pct, 0, 100) / 100.0
            d_n  = np.clip(data_quality, 0, 1)
            return float((r_n + e_n + m_n + d_n) / 4.0)

    # ------------------------------------------------------------------
    def score_all(
        self,
        vehicle_metrics: Dict[int, Dict[str, float]],
    ) -> Dict[int, float]:
        """
        Score every vehicle in the metrics dict.

        Parameters
        ----------
        vehicle_metrics : {vehicle_id: {rssi_avg_dbm, residual_energy_pct,
                                         memory_free_pct, data_quality}}

        Returns
        -------
        {vehicle_id: selection_score}
        """
        scores: Dict[int, float] = {}
        for vid, m in vehicle_metrics.items():
            scores[vid] = self.score(
                rssi_dbm        = m.get("rssi_avg_dbm", -80.0),
                energy_pct      = m.get("residual_energy_pct", 50.0),
                memory_free_pct = m.get("memory_free_pct", 80.0),
                data_quality    = m.get("data_quality", 0.5),
            )
        return scores

    # ------------------------------------------------------------------
    def select_top_k(
        self,
        vehicle_metrics: Dict[int, Dict[str, float]],
        k: int,
    ) -> List[int]:
        """
        Return IDs of the top-k vehicles ranked by FLBFLVS score.

        Parameters
        ----------
        vehicle_metrics : {vehicle_id: metric_dict}
        k               : number of vehicles to select

        Returns
        -------
        List of selected vehicle IDs (descending score order)
        """
        scores = self.score_all(vehicle_metrics)
        ranked = sorted(scores, key=lambda v: scores[v], reverse=True)
        return ranked[:k]

    # ------------------------------------------------------------------
    def select_fraction(
        self,
        vehicle_metrics: Dict[int, Dict[str, float]],
        fraction: float = 0.7,
        min_clients: int = 2,
    ) -> List[int]:
        """Select top `fraction` of vehicles (at least min_clients)."""
        k = max(min_clients, int(len(vehicle_metrics) * fraction))
        return self.select_top_k(vehicle_metrics, k)

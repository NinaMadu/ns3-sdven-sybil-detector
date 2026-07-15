"""
ensemble_live — live Eq 3.18 OBU fusion head + Eq 3.20 RSU ensemble ŷ_ens, applied
to a live cᵢ DataFrame (the real-time twin of fusion/train_fusion_head.py +
fusion/rsu_ensemble.py).

Eq 3.18:  ŷ_i = σ( w · [φ_rssi‖φ_temp‖φ_trust] + b )   — weights loaded from the
          deployment export fusion_head_weights.json (train-split mean-impute for
          any absent φ block, exactly as trained).
Eq 3.20:  ŷ_ens = Σ_k λ_k·term_k / Σ_k λ_k   over the terms PRESENT for that window
          (renormalised), terms = [ŷ_i, p̄_temp, p̄_rssi], λ from ensemble_lambdas.json.

p̄_temp / p̄_rssi come from the RSU XGB predictors (added later); until then only ŷ_i
is present, so ŷ_ens == ŷ_i (renormalised) — nullable-graceful, matching the offline
weighted_score. Output columns: y_hat_i_fused, y_hat_ens (appended to the cᵢ frame).
"""

import json
import os

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
FUSION_OUT = os.path.join(_HERE, "..", "fusion", "outputs")
DEFAULT_WEIGHTS = os.path.join(FUSION_OUT, "fusion_head_weights.json")
DEFAULT_LAMBDAS = os.path.join(FUSION_OUT, "ensemble_lambdas.json")

TERMS = ["y_hat_i_fused", "p_bar_temp", "p_bar_rssi"]   # ŷ_i, p̄_temp, p̄_rssi


class FusionHeadLive:
    """Eq 3.18 linear head applied to live φ (weights loaded, never refit)."""

    def __init__(self, phi_cols, weight, bias, impute_fill):
        self.phi_cols = phi_cols
        self.w = np.asarray(weight, dtype=np.float64)         # (80,)
        self.b = float(bias)
        self.fill = impute_fill                                # {phi_col: train mean}

    @classmethod
    def load(cls, path=DEFAULT_WEIGHTS):
        d = json.loads(open(path).read())
        return cls(d["phi_cols"], d["weight"], d["bias"], d["impute_fill"])

    def apply(self, df):
        """Add `y_hat_i_fused` = σ(w·φ+b) per row; absent φ blocks mean-imputed."""
        df = df.copy()
        # columns that exist in the frame; genuinely-missing φ blocks -> fill value
        X = np.empty((len(df), len(self.phi_cols)), dtype=np.float64)
        for j, c in enumerate(self.phi_cols):
            if c in df.columns:
                X[:, j] = df[c].fillna(self.fill[c]).to_numpy(dtype=np.float64)
            else:
                X[:, j] = self.fill[c]
        logit = X @ self.w + self.b
        df["y_hat_i_fused"] = 1.0 / (1.0 + np.exp(-logit))
        return df


def _load_lambdas(path=DEFAULT_LAMBDAS):
    d = json.loads(open(path).read())["lambda"]
    return np.array([d["lambda1_yhat_i"], d["lambda2_pbar_temp"], d["lambda3_pbar_rssi"]],
                    dtype=np.float64)


def _weighted_score(mat, lam):
    """Renormalise λ over the terms present (NaN = absent). Verbatim rsu_ensemble logic."""
    w = np.where(np.isnan(mat), 0.0, lam[None, :])
    denom = w.sum(axis=1)
    num = np.nansum(np.where(np.isnan(mat), 0.0, mat) * w, axis=1)
    return np.divide(num, denom, out=np.full(len(mat), np.nan), where=denom > 0)


def add_ensemble(df, lam=None):
    """Add `y_hat_ens` (Eq 3.20) from y_hat_i_fused (+ p_bar_temp/p_bar_rssi if present)."""
    lam = _load_lambdas() if lam is None else np.asarray(lam, dtype=np.float64)
    mat = np.full((len(df), 3), np.nan)
    for k, t in enumerate(TERMS):
        if t in df.columns:
            mat[:, k] = df[t].to_numpy(dtype=np.float64)
    df = df.copy()
    df["y_hat_ens"] = _weighted_score(mat, lam)
    return df


def enrich(df, head=None, lam=None):
    """Convenience: Eq 3.18 head then Eq 3.20 ensemble on a live cᵢ frame."""
    head = head or FusionHeadLive.load()
    return add_ensemble(head.apply(df), lam=lam)

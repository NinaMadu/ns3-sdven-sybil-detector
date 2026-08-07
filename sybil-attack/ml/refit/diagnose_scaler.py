"""
diagnose_scaler — pick a scaler design by MEASURING φ stability, not z magnitude.

The A/B showed the head refit does not transfer: on a fresh seed the φ centroid sat L2 2.08
from the cloud the head was fitted on (that cloud's own norm 2.68) and saturation went
15.4% -> 41%. So the metric that matters is not "is mean |z| small" but "does φ land in the
same place on a run the scaler was NOT fitted on". This script scores that directly.

Candidates
  july      the shipped scaler (mean_/scale_ from the July runs)              [status quo]
  refit     StandardScaler refitted on the six current runs
  refit+bin refit, but temp_id_change_flag left as a raw 0/1 indicator
  refit+flr refit+bin, plus a floor under scale_ (no feature may be amplified > 1/FLOOR)

temp_id_change_flag is the reason for the +bin variant: it is a RARE BINARY event, so its
variance is small by construction and z-scoring it turns one pseudonym change into z=157
(July) — refitting alone does not fix that, it just changes the constant. A 0/1 indicator
fed as 0/1 is the honest encoding.

HOLD-OUT is the whole point: scalers are fitted on the six refit runs only, then φ stability
is measured on mock_ablation/refit_ab/* which none of them saw.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

_HERE = Path(__file__).resolve().parent
_ML = _HERE.parent
sys.path.insert(0, str(_ML / "analyzers" / "temporal_gru"))
import predict as P                                       # noqa: E402

BINARY_FEATURES = {"temp_id_change_flag"}
SCALE_FLOOR = 0.05          # no feature amplified more than 20x
FIT_RUNS = [r for r, _ in __import__("build_phi_dataset").DEF_RUNS] \
    if (_HERE / "build_phi_dataset.py").exists() else []
HOLDOUT_RUNS = ["mock_ablation/refit_ab/baseline", "mock_ablation/refit_ab/refit"]


def collect(run_rel, predictor):
    X, L, meta = P.build_windows_live(_ML.parent / run_rel, run_id=run_rel)
    return X, L, meta


def make_scalers(Xfit_flat, july):
    out = {"july": (july.mean_.copy(), july.scale_.copy())}
    sc = StandardScaler().fit(Xfit_flat)
    out["refit"] = (sc.mean_.copy(), sc.scale_.copy())

    m, s = sc.mean_.copy(), sc.scale_.copy()
    for i, c in enumerate(P.SEQ_FEATURE_COLS):
        if c in BINARY_FEATURES:
            m[i], s[i] = 0.0, 1.0                          # keep 0/1 as 0/1
    out["refit+bin"] = (m.copy(), s.copy())

    s2 = np.maximum(s, SCALE_FLOOR)
    # a feature that was CONSTANT while fitting carries no information: centre it to 0
    s2[sc.var_ == 0.0] = 1.0
    out["refit+flr"] = (m.copy(), s2)
    return out


def phi_for(predictor, X, L, mean_, scale_, var_zero_idx):
    n, w, f = X.shape
    flat = X.reshape(n * w, f).copy()
    for i in var_zero_idx:
        flat[:, i] = mean_[i]                              # neutralise constant-in-fit features
    Z = ((flat - mean_) / scale_).reshape(n, w, f).astype(np.float32)
    phi, prob = predictor._extract_phi(Z, L)
    return Z, phi, prob


def main():
    predictor = P.TemporalPredictor.load(
        model_dir=_ML / "analyzers" / "temporal_gru" / "outputs" / "temporal_vehicle_tier")
    P.TemporalPredictor._drift_warned = P.TemporalPredictor._degenerate_warned = True
    july = predictor.scaler

    sys.path.insert(0, str(_HERE))
    fit_runs = [r for r, _ in __import__("build_phi_dataset").DEF_RUNS]

    print("collecting raw windows ...")
    fit_data = {}
    for r in fit_runs:
        X, L, meta = collect(r, predictor)
        if X is not None:
            fit_data[r] = (X, L, meta)
            print(f"  {r:52s} {X.shape[0]:7d} windows")
    hold_data = {}
    for r in HOLDOUT_RUNS:
        X, L, meta = collect(r, predictor)
        if X is not None:
            hold_data[r] = (X, L, meta)
            print(f"  {r:52s} {X.shape[0]:7d} windows  [HELD OUT]")

    Xfit_flat = np.concatenate([v[0].reshape(-1, 10) for v in fit_data.values()])
    scalers = make_scalers(Xfit_flat, july)

    print("\n" + "=" * 96)
    for name, (m, s) in scalers.items():
        vz = np.flatnonzero(july.var_ == 0.0) if name == "july" else \
            np.flatnonzero(StandardScaler().fit(Xfit_flat).var_ == 0.0)
        cents, sats, zmaxes = [], [], []
        per_run = {}
        for label, (X, L, _) in {**fit_data, **hold_data}.items():
            Z, phi, prob = phi_for(predictor, X, L, m, s, vz)
            per_run[label] = phi.mean(0)
            sats.append(float((np.abs(phi) >= 0.99).mean()))
            zmaxes.append(float(np.abs(Z).max()))
        C = np.stack(list(per_run.values()))
        centroid_fit = C[:len(fit_data)].mean(0)
        # the number that decides it: how far the HELD-OUT runs' φ land from the fit cloud
        d_hold = [float(np.linalg.norm(per_run[r] - centroid_fit)) for r in hold_data]
        # and how much the fit runs disagree among themselves
        d_fit = [float(np.linalg.norm(C[i] - centroid_fit)) for i in range(len(fit_data))]
        print(f"{name:12s} phi_sat {100*np.mean(sats):5.1f}%   max|z| {max(zmaxes):8.1f}   "
              f"||phi_c|| {np.linalg.norm(centroid_fit):5.2f}")
        print(f"{'':12s}   spread WITHIN fit runs  mean {np.mean(d_fit):5.2f}  max {max(d_fit):5.2f}")
        print(f"{'':12s}   distance of HELD-OUT runs {[round(x,2) for x in d_hold]}"
              f"   <-- lower is what makes a refit transfer")
    print("=" * 96)


if __name__ == "__main__":
    main()

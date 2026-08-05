"""
temporal_gru/predict.py — label-free, manifest-free real-time inference for the
temporal GRU analyzer (v4), the ANCHOR of the fusion c_i (Phase 1).

Faithfully reproduces temporal_gru_seq_v4.ipynb's feature extraction and windowing,
but drops the training-only coupling (identity-manifest subsample, phase-table
labels, split). Loads the persisted artifacts — it never refits the scaler:
    outputs/temporal_vehicle_tier/temporal_federated_gru_hier.pt   (bi-GRU state_dict)
    outputs/temporal_vehicle_tier/scaler.pkl                       (StandardScaler)
    outputs/temporal_vehicle_tier/config.json                      (W, features, dims)

Windowing (per the notebook, VERBATIM logic minus labels):
  * input  = communication_log v2v_beacon rows with receiver_role == vehicle;
  * dedup  = observer_count per beacon event (nunique receiver_id over BEACON_KEY);
  * per (run_id, receiver_id, claimed_node_id) sorted by receive_time, SLIDING
    W=10-beacon sequences, step=1 (needs >= W beacons to yield any window);
  * 10 sequence features (SEQ_FEATURE_COLS); window_start = first beacon's time.
Export snaps window_start to the shared 2 s grid and MEAN-pools -> one row per
(run_id, claimed_node_id, window_start_seconds) with phi_temp_0..31 + p_temp_0..6.

API:
  p = TemporalPredictor.load()
  df = p.score_logs(run_dir, t=None, run_id="live")   # -> spine-schema DataFrame
"""

import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1] / "fusion"))   # ml/fusion for snap_grid
import identity_manifest as IDM          # noqa: E402  (snap_grid only)

MODEL_DIR = _HERE / "outputs" / "temporal_vehicle_tier"

# feature/window contract (mirrors config.json; asserted against it at load)
SEQ_FEATURE_COLS = ["delta_t", "temp_id_change_flag", "bsm_x", "bsm_y", "bsm_speed",
                    "bsm_heading", "packet_size", "delay", "observer_count",
                    "bsm_msg_count_delta"]
WINDOW_W, WINDOW_STEP = 10, 1
# Mean |z| above which a live feature is reported as outside its training scale.
# Lowered 5.0 -> 3.0 on 2026-08-05: at 5.0 this guard stayed SILENT through a run
# whose worst feature sat at mean |z| = 4.48 (bsm_msg_count_delta) while the GRU's
# state was 31 % saturated and p_temp_0 had collapsed 800x — precisely the failure
# it was written to catch. This is a MEAN |z|, not a single sample: 3.0 means the
# average observation is three sigma out, which no legitimate mobility or timing
# noise produces.
DRIFT_ABS_Z_WARN = 3.0

# Output-side degeneracy thresholds. Input drift is only a proxy; these fire on the
# symptom itself, so a distribution shift that keeps every feature under the |z| bar
# but still saturates the recurrent state cannot pass silently.
#   PHI_SAT_FRAC_WARN  fraction of |phi| >= PHI_SAT_LEVEL (GRU state is tanh-bounded,
#                      so |phi| pinned at 1 means the cell has stopped discriminating)
#   P0_COLLAPSE_WARN   mean p_temp_0. The training cᵢ sits at 0.637 and calls the
#                      modal window legitimate 66 % of the time; a live mean near zero
#                      means the analyzer has stopped being able to say "legitimate".
PHI_SAT_LEVEL, PHI_SAT_FRAC_WARN = 0.99, 0.25
P0_COLLAPSE_WARN, P0_TRAIN_REFERENCE = 0.05, 0.637
GRU_HIDDEN, N_CLASSES, DROPOUT, BIDIRECTIONAL = 16, 7, 0.3, True
BEACON_KEY = ["run_id", "real_node_id", "claimed_node_id", "bsm_temporary_id", "receive_time"]

# raw comm-log columns needed (features + dedup key + row filter); NO label cols.
NEED_COLS = {"receive_time", "flow", "receiver_role", "receiver_id", "real_node_id",
             "claimed_node_id", "packet_size", "delay", "bsm_temporary_id",
             "bsm_msg_count", "bsm_x", "bsm_y", "bsm_speed", "bsm_heading"}


class TemporalGRU(nn.Module):
    """Bi-GRU exactly as trained (phi_temp = 2*hidden = 32)."""

    def __init__(self, n_feat=len(SEQ_FEATURE_COLS), hidden=GRU_HIDDEN,
                 n_classes=N_CLASSES, dropout=DROPOUT, bidirectional=BIDIRECTIONAL):
        super().__init__()
        self.bi = bidirectional
        self.gru = nn.GRU(n_feat, hidden, batch_first=True, bidirectional=bidirectional)
        out_dim = hidden * (2 if bidirectional else 1)
        self.drop = nn.Dropout(dropout)
        self.head = nn.Linear(out_dim, n_classes)

    def forward(self, x, lengths, return_phi=False):
        packed = nn.utils.rnn.pack_padded_sequence(x, lengths.cpu(), batch_first=True,
                                                   enforce_sorted=False)
        _, h_n = self.gru(packed)
        phi = torch.cat([h_n[-2], h_n[-1]], dim=1) if self.bi else h_n[-1]
        logits = self.head(self.drop(phi))
        return (logits, phi) if return_phi else logits


def build_windows_live(run_dir, t=None, run_id="live", W=WINDOW_W, step=WINDOW_STEP,
                       nrows=None, rows=None):
    """Causal, label-free twin of the notebook's build_windows.

    `rows`: pre-read comm-log DataFrame already filtered to <= t (the daemon's LogCache
    fast path); when given, the CSV read is skipped. Returns (X[N,W,10] float32, L[N] int,
    meta DataFrame with run_id/receiver_id/claimed_node_id/window_start_seconds), or Nones.
    """
    if rows is not None:
        df = rows
    else:
        df = pd.read_csv(Path(run_dir) / "communication_log.csv",
                         usecols=lambda c: c in NEED_COLS, nrows=nrows)
        if t is not None:
            df = df[df["receive_time"] <= float(t)]
    df = df[(df["flow"] == "v2v_beacon") & (df["receiver_role"] == "vehicle")].copy()
    if df.empty:
        return None, None, None
    df["run_id"] = run_id

    # observer_count = # distinct receivers per beacon event (dedup feature)
    dup = (df.groupby(BEACON_KEY)["receiver_id"].nunique()
             .rename("observer_count").reset_index())
    df = df.merge(dup, on=BEACON_KEY, how="left")

    Xs, Ls, meta = [], [], []
    for (run, rid, cid), g in df.sort_values("receive_time").groupby(
            ["run_id", "receiver_id", "claimed_node_id"], sort=False):
        if len(g) < W:                       # need >= W beacons for any sliding window
            continue
        g = g.reset_index(drop=True)
        delta_t = g["receive_time"].diff().fillna(0.0).values
        msg_delta = g["bsm_msg_count"].diff().fillna(0.0).values
        tid_chg = (g["bsm_temporary_id"] != g["bsm_temporary_id"].shift(1)
                   ).fillna(False).astype(float).values
        feat = np.column_stack([delta_t, tid_chg, g["bsm_x"].values, g["bsm_y"].values,
                                g["bsm_speed"].values, g["bsm_heading"].values,
                                g["packet_size"].values, g["delay"].values,
                                g["observer_count"].values, msg_delta]).astype(np.float32)
        tvec = g["receive_time"].values
        n = len(feat)
        for s in range(0, n - W + 1, step):
            Xs.append(feat[s:s + W])
            Ls.append(W)
            meta.append({"run_id": run, "receiver_id": rid, "claimed_node_id": cid,
                         "window_start_seconds": float(tvec[s])})
    if not Xs:
        return None, None, None
    return (np.stack(Xs), np.array(Ls, np.int32), pd.DataFrame(meta))


class TemporalPredictor:
    """Trained bi-GRU + persisted scaler, for live sequence scoring."""

    def __init__(self, model, scaler, device="cpu"):
        self.model = model.to(device).eval()
        self.scaler = scaler
        self.device = device

    @classmethod
    def load(cls, model_dir=MODEL_DIR, device="cpu"):
        cfg = json.loads((Path(model_dir) / "config.json").read_text())
        assert cfg["features"] == SEQ_FEATURE_COLS, "feature mismatch vs config.json"
        assert cfg["window_W"] == WINDOW_W and cfg["phi_dim"] == GRU_HIDDEN * 2
        model = TemporalGRU()
        sd = torch.load(Path(model_dir) / "temporal_federated_gru_hier.pt",
                        map_location=device)
        model.load_state_dict(sd)
        with open(Path(model_dir) / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
        return cls(model, scaler, device)

    def _degenerate_feature_idx(self):
        """Indices of features that were CONSTANT while the scaler was fitted.

        StandardScaler records var_ == 0 for such a feature and falls back to
        scale_ == 1.0, so any later drift is fed to the model as a RAW difference
        rather than a standard score. `packet_size` is the live example: it was a
        flat 120 B throughout training, then commit c970786 (2026-08-02) made
        beacons carry real signature bytes on the wire (248 B classical, 3193 B
        PQC). That is z = 3073 for a feature the model was never able to learn
        from, and it saturated 30 of the 32 tanh GRU dims — the analyzer returned
        one constant class for every identity.
        """
        var = getattr(self.scaler, "var_", None)
        if var is None:
            return np.array([], dtype=int)
        return np.flatnonzero(np.asarray(var) == 0.0)

    def _scale(self, X):
        """Apply the persisted StandardScaler per timestep (all windows full W).

        Zero-variance-in-training features are pinned to the scaler's own mean
        (z = 0) before transforming. This is information-PRESERVING, not a
        correction: a feature that never varied while the model trained cannot
        have contributed anything to its weights, so neutralising it removes
        drift noise without discarding learned signal. Everything else is
        transformed exactly as before, so healthy runs are bit-identical.
        """
        n, w, f = X.shape
        flat = X.reshape(n * w, f)
        deg = self._degenerate_feature_idx()
        if len(deg):
            flat = flat.copy()
            for i in deg:
                flat[:, i] = self.scaler.mean_[i]
        Z = self.scaler.transform(flat)
        self._warn_on_drift(Z)
        return Z.reshape(n, w, f).astype(np.float32)

    # emit the drift warning once per process, not once per scoring window
    _drift_warned = False

    def _warn_on_drift(self, Z, thresh=DRIFT_ABS_Z_WARN):
        """Loud warning when a live feature sits far outside its training scale.

        The failure this guards against is silent: the GRU keeps returning
        confident-looking probabilities while its hidden state is saturated. Had
        this existed on 2026-08-02 the packet_size regression would have been
        caught on the first run instead of via a full A/B campaign.
        """
        if TemporalPredictor._drift_warned:
            return
        mean_abs_z = np.abs(Z).mean(axis=0)
        bad = [(SEQ_FEATURE_COLS[i], float(mean_abs_z[i]))
               for i in np.flatnonzero(mean_abs_z > thresh)]
        if bad:
            TemporalPredictor._drift_warned = True
            detail = ", ".join(f"{c} |z|={z:.1f}" for c, z in bad)
            print(f"[temporal_gru] WARNING: live features far outside the training "
                  f"scale (mean |z| > {thresh}): {detail}. The GRU's tanh state may be "
                  f"saturated and its output degenerate — check phi variance before "
                  f"trusting p_temp.", flush=True)

    # emit the degeneracy warning once per process, like the drift one
    _degenerate_warned = False

    def _degeneracy(self, phi, prob):
        """(is_degenerate, [reasons]) for one scored batch.

        Split out from the warning so the verdict can travel with the DATA, not just
        the log: score_logs stamps it onto every row as `temporal_degenerate` and the
        live cᵢ builder uses it to withhold the class tokens. Evaluated per batch
        because degeneracy is a property of this run's feature distribution, not of
        the weights.
        """
        sat = float((np.abs(phi) >= PHI_SAT_LEVEL).mean())
        p0 = float(prob[:, 0].mean())
        reasons = []
        if sat > PHI_SAT_FRAC_WARN:
            reasons.append(f"{100 * sat:.0f}% of phi pinned at |{PHI_SAT_LEVEL}| "
                           f"(state saturated)")
        if p0 < P0_COLLAPSE_WARN:
            reasons.append(f"mean p_temp_0={p0:.4f} vs training {P0_TRAIN_REFERENCE} "
                           f"(cannot output 'legitimate')")
        return bool(reasons), reasons

    def _warn_on_degenerate_output(self, phi, prob):
        """Warn when the OUTPUT is degenerate, whatever the inputs looked like.

        _warn_on_drift watches the inputs, which is a proxy and an imperfect one:
        on 2026-08-05 every feature sat below the |z| bar in force at the time, yet
        31 % of phi was pinned at |1| and p_temp_0 averaged 0.0008 against a training
        mean of 0.637 — the analyzer had stopped being able to output "legitimate"
        at all, and nothing said so. Downstream this is not a small error: the LLM
        reads features.temporal.pred as its variant evidence, so a degenerate class
        head is reported as a confident wrong attack type rather than as no evidence.
        """
        degenerate, problems = self._degeneracy(phi, prob)
        self._last_degenerate = degenerate
        if TemporalPredictor._degenerate_warned:
            return
        if degenerate:
            TemporalPredictor._degenerate_warned = True
            print(f"[temporal_gru] WARNING: output is DEGENERATE — "
                  f"{'; '.join(problems)}. p_temp/pred are not trustworthy this run; "
                  f"treat the temporal class label as absent rather than as evidence.",
                  flush=True)

    @torch.no_grad()
    def _extract_phi(self, X, L, batch=65536):
        phis, logits = [], []
        for i in range(0, len(L), batch):
            xb = torch.tensor(X[i:i + batch], dtype=torch.float32).to(self.device)
            lb = torch.tensor(L[i:i + batch], dtype=torch.long)
            logit, phi = self.model(xb, lb, return_phi=True)
            logits.append(logit.cpu().numpy())
            phis.append(phi.cpu().numpy())
        logit = np.concatenate(logits)
        phi = np.concatenate(phis)
        e = np.exp(logit - logit.max(1, keepdims=True))
        prob = e / e.sum(1, keepdims=True)
        self._warn_on_degenerate_output(phi, prob)
        return phi, prob                     # (N,32), (N,7)

    def score_logs(self, run_dir, t=None, run_id="live", nrows=None, rows=None):
        X, L, meta = build_windows_live(run_dir, t=t, run_id=run_id, nrows=nrows, rows=rows)
        if X is None:
            return pd.DataFrame()
        phi, prob = self._extract_phi(self._scale(X), L)

        out = meta.copy()
        out["window_start_seconds"] = IDM.snap_grid(out["window_start_seconds"].to_numpy())
        for i in range(phi.shape[1]):
            out[f"phi_temp_{i}"] = phi[:, i]
        for k in range(prob.shape[1]):
            out[f"p_temp_{k}"] = prob[:, k]
        # snap+mean-pool to one row per (run_id, claimed, 2 s cell) — matches export.
        key = ["run_id", "claimed_node_id", "window_start_seconds"]
        val_cols = [f"phi_temp_{i}" for i in range(phi.shape[1])] + \
                   [f"p_temp_{k}" for k in range(prob.shape[1])]
        pooled = out.groupby(key, as_index=False)[val_cols].mean()
        # Batch-level verdict carried on every row, so downstream consumers can decide
        # whether to trust p_temp WITHOUT re-deriving it. p_temp/phi_temp themselves are
        # left intact: this is a label on the data, never a modification of it, and the
        # Eq 3.18/3.20 fusion path keeps using phi_temp exactly as before.
        pooled["temporal_degenerate"] = int(getattr(self, "_last_degenerate", False))
        return pooled


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Score a run's comm log with the trained GRU.")
    ap.add_argument("run_dir")
    ap.add_argument("--t", type=float, default=None)
    ap.add_argument("--run-id", default="live")
    ap.add_argument("--nrows", type=int, default=None)
    ap.add_argument("--model-dir", default=str(MODEL_DIR))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    p = TemporalPredictor.load(args.model_dir)
    df = p.score_logs(args.run_dir, t=args.t, run_id=args.run_id, nrows=args.nrows)
    print(f"scored {len(df):,} (run_id, claimed_id, window) rows")
    if len(df):
        phicols = [f"phi_temp_{i}" for i in range(32)]
        pcols = [f"p_temp_{k}" for k in range(7)]
        print("cols:", list(df.columns))
        print("|phi_temp| max:", float(np.abs(df[phicols].to_numpy()).max()))
        print("p_temp row-sum range: [%.4f, %.4f] (should be ~1)" % (
            df[pcols].sum(1).min(), df[pcols].sum(1).max()))
        print("argmax class dist:", pd.Series(df[pcols].to_numpy().argmax(1)).value_counts().to_dict())
        print(df.head(3).to_string())
    if args.out and len(df):
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        df.to_parquet(args.out, index=False)
        print("wrote", args.out)

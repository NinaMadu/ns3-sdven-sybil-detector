"""
rssi_cnn/predict.py — label-free, manifest-free real-time inference for the RSSI
CNN analyzer (v3) (Phase 1).

Faithfully reproduces RSSI_Model1_CNN_Federated_v3.ipynb's channel construction and
(C,W) sliding windows, minus the training-only coupling (identity-manifest subsample,
phase-table labels, split). Loads the persisted artifact — never refits the channel
scaler (chan_mean/chan_std live INSIDE the .pt):
    outputs/v3/rssi_cnn_federated_v3.pt  {state_dict, fl_config, in_channels,
                                          chan_mean(4), chan_std(4), threshold}

Windowing (per the notebook, VERBATIM logic minus labels):
  * input = rssi_verification_log rows (RSSI_USE), dedup on the 5 cols;
  * rssi_centred = per-(run,observer) mean-centred RSSI, then a p1/p99 clip;
  * 4 channels on the per-(run,observer,claimed) series:
      ch0 rssi_centred · ch1 first-diff · ch2 rolling-std(w=3) · ch3 inter-beacon dt (clip 0..5);
  * left-pad short series to W (edge) so every id yields >=1 window; sliding (C,W), step 1;
  * z-score each channel with the PERSISTED chan_mean/chan_std.
Export snaps window_start to the 2 s grid and MEAN-pools -> phi_rssi_0..31 + y_hat_i.

Persistence gaps (documented): the per-observer centring mean and the p1/p99 clip are
data-dependent and NOT saved. Live uses the causal (<=t) mean and a p1/p99 clip over the
available rows — a small tail effect; the persisted chan z-score dominates scaling.

API:
  p = RSSIPredictor.load()
  df = p.score_logs(run_dir, t=None, run_id="live")   # -> spine-schema DataFrame
"""

import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1] / "fusion"))   # ml/fusion for snap_grid
import identity_manifest as IDM          # noqa: E402  (snap_grid only)

MODEL_PT = _HERE / "outputs" / "v3" / "rssi_cnn_federated_v3.pt"

RSSI_USE = ["time", "observer_vehicle_id", "observed_claimed_id", "observed_real_id", "rssi_dbm"]
DEDUP_COLS = ["time", "observer_vehicle_id", "observed_claimed_id", "observed_real_id", "rssi_dbm"]
WINDOW_W = 10


class RSSIAnalyzerCNN(nn.Module):
    """Compact CNN exactly as trained; phi_RSSI = avg/max-pooled hidden (F=32)."""

    def __init__(self, F, K, pooling, dropout, in_channels):
        super().__init__()
        P = K // 2
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels, F, K, padding=P), nn.ReLU(), nn.Dropout(dropout),
            nn.Conv1d(F, F, K, padding=P), nn.ReLU(), nn.Dropout(dropout))
        self.pool = pooling
        self.head = nn.Linear(F, 1)

    def forward(self, x, return_phi=False):
        h = self.conv(x)
        phi = h.mean(-1) if self.pool == "avg" else h.max(-1).values   # (B, F)
        logit = self.head(phi).squeeze(-1)
        return (logit, phi) if return_phi else logit


def build_windows_live(run_dir, t=None, run_id="live", W=WINDOW_W, nrows=None):
    """Causal, label-free twin of RSSIWindowDataset.

    Returns (X[N,4,W] float32, meta DataFrame). Empty -> (None, None).
    Channels are NOT yet z-scored here (predictor applies persisted chan stats).
    """
    run_dir = Path(run_dir)
    df = pd.read_csv(run_dir / "rssi_verification_log.csv",
                     usecols=lambda c: c in set(RSSI_USE), nrows=nrows)
    if t is not None:
        df = df[df["time"] <= float(t)]
    if df.empty:
        return None, None
    df = df.drop_duplicates(subset=DEDUP_COLS)
    for c in ("observer_vehicle_id", "observed_claimed_id", "observed_real_id"):
        df[c] = df[c].astype("int32")
    df["run_id"] = run_id

    # per-(run,observer) centring (causal mean over available rows), then p1/p99 clip
    df = df.sort_values(["run_id", "observer_vehicle_id", "observed_claimed_id", "time"])
    df["rssi_centred"] = (df.groupby(["run_id", "observer_vehicle_id"])["rssi_dbm"]
                          .transform(lambda s: s - s.mean()).astype("float32"))
    p1, p99 = np.percentile(df["rssi_centred"].values, [1, 99])
    df["rssi_centred"] = np.clip(df["rssi_centred"].values, p1, p99).astype("float32")
    df = df.reset_index(drop=True)

    wins, claimed, obs, run, ssec = [], [], [], [], []
    for (rid, o, c), grp in df.groupby(
            ["run_id", "observer_vehicle_id", "observed_claimed_id"], sort=False):
        grp = grp.sort_values("time")
        s = grp["rssi_centred"].values.astype(np.float32)
        tv = grp["time"].values.astype(np.float64)
        n0 = len(s)
        d = np.diff(s, prepend=s[0]).astype(np.float32)                          # ch1
        vol = (pd.Series(s).rolling(3, min_periods=1).std()
               .fillna(0.0).to_numpy().astype(np.float32))                       # ch2
        dt = np.clip(np.diff(tv, prepend=tv[0]), 0.0, 5.0).astype(np.float32)    # ch3
        feats = np.stack([s, d, vol, dt], axis=0)                               # (4, n0)
        if n0 < W:
            feats = np.pad(feats, ((0, 0), (W - n0, 0)), mode="edge")
        n = feats.shape[1]
        for st in range(n - W + 1):
            j = min(st, len(tv) - 1)
            wins.append(feats[:, st:st + W])
            claimed.append(int(c)); obs.append(int(o)); run.append(rid)
            ssec.append(float(tv[j]))
    if not wins:
        return None, None
    meta = pd.DataFrame({"run_id": run, "claimed_node_id": claimed,
                         "receiver_id": obs, "window_start_seconds": ssec})
    return np.stack(wins).astype(np.float32), meta


class RSSIPredictor:
    """Trained CNN + persisted per-channel z-score stats, for live scoring."""

    def __init__(self, model, chan_mean, chan_std, device="cpu"):
        self.model = model.to(device).eval()
        self.chan_mean = np.asarray(chan_mean, dtype=np.float32).reshape(1, -1, 1)
        self.chan_std = np.asarray(chan_std, dtype=np.float32).reshape(1, -1, 1)
        self.device = device

    @classmethod
    def load(cls, model_pt=MODEL_PT, device="cpu"):
        ckpt = torch.load(model_pt, map_location=device, weights_only=False)
        fl = ckpt["fl_config"]
        model = RSSIAnalyzerCNN(fl["filters"], fl["kernel_size"], fl["pooling"],
                                fl["dropout"], in_channels=ckpt["in_channels"])
        model.load_state_dict(ckpt["state_dict"])
        return cls(model, ckpt["chan_mean"], ckpt["chan_std"], device)

    @torch.no_grad()
    def _extract(self, X, batch=4096):
        Xs = (X - self.chan_mean) / self.chan_std          # persisted per-channel z-score
        phis, logits = [], []
        for i in range(0, len(Xs), batch):
            xb = torch.tensor(Xs[i:i + batch], dtype=torch.float32).to(self.device)
            logit, phi = self.model(xb, return_phi=True)
            logits.append(logit.cpu().numpy())
            phis.append(phi.cpu().numpy())
        logit = np.concatenate(logits)
        phi = np.concatenate(phis)
        y_hat_i = 1.0 / (1.0 + np.exp(-logit))
        return phi, y_hat_i                                 # (N,32), (N,)

    def score_logs(self, run_dir, t=None, run_id="live", nrows=None):
        X, meta = build_windows_live(run_dir, t=t, run_id=run_id, nrows=nrows)
        if X is None:
            return pd.DataFrame()
        phi, y_hat_i = self._extract(X)

        out = meta[["run_id", "claimed_node_id"]].copy()
        out["window_start_seconds"] = IDM.snap_grid(meta["window_start_seconds"].to_numpy())
        out["y_hat_i"] = y_hat_i.astype(np.float32)
        for i in range(phi.shape[1]):
            out[f"phi_rssi_{i}"] = phi[:, i].astype(np.float32)
        key = ["run_id", "claimed_node_id", "window_start_seconds"]
        val_cols = ["y_hat_i"] + [f"phi_rssi_{i}" for i in range(phi.shape[1])]
        return out.groupby(key, as_index=False)[val_cols].mean()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Score a run's rssi log with the trained CNN.")
    ap.add_argument("run_dir")
    ap.add_argument("--t", type=float, default=None)
    ap.add_argument("--run-id", default="live")
    ap.add_argument("--nrows", type=int, default=None)
    ap.add_argument("--model-pt", default=str(MODEL_PT))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    p = RSSIPredictor.load(args.model_pt)
    df = p.score_logs(args.run_dir, t=args.t, run_id=args.run_id, nrows=args.nrows)
    print(f"scored {len(df):,} (run_id, claimed_id, window) rows")
    if len(df):
        phicols = [f"phi_rssi_{i}" for i in range(32)]
        print("cols:", list(df.columns))
        print("|phi_rssi| max: %.3f" % float(np.abs(df[phicols].to_numpy()).max()))
        print("y_hat_i range: [%.3f, %.3f]" % (df["y_hat_i"].min(), df["y_hat_i"].max()))
        print(df.head(3).to_string())
    if args.out and len(df):
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        df.to_parquet(args.out, index=False)
        print("wrote", args.out)

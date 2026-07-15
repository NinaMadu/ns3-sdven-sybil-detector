"""
Eq 3.18 — OBU feature-fusion head for the full-mode pipeline.

    ŷ_i = σ( w_rssi·φ_rssi + w_temp·φ_temp + w_trust·φ_trust )

The paper defines ŷ_i as a TRAINED linear head over the CONCATENATED vehicle-tier
feature vectors (not a scalar weighted sum). φ dims: rssi 32 ‖ temp 32 ‖ trust 16
= 80-d → Linear(80→1)+σ. Stage 1 skipped this and let the RSSI-only `y_hat_i`
stand in; Stage 2 trains the real 3-way signal so the Eq 3.20 ensemble is faithful.

Consumes ml/fullmode/context/c_i.parquet (all 80 φ columns already present).
Trains on the `train` split only, early-stops on `val`, then scores EVERY window.
Missing φ blocks (a source didn't cover a window, ~2.5%) are mean-imputed from the
train split — the φ are already model-scaled, so the mean is a neutral fill.

Output: notebooks/outputs/fusion_head.parquet  (JOIN_KEY + y_hat_i_fused)

Run in ml/.venv (torch):  python ml/fusion/train_fusion_head.py
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

# constants.py lives in the sibling fullmode/ package
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "common"))
import constants as C  # noqa: E402

DEF_CI = os.path.join(_HERE, "..", "llm", "common", "context", "c_i.parquet")
DEF_OUT = os.path.join(C.OUTPUTS_DIR, "fusion_head.parquet")

# Eq 3.18 concat order: rssi(32) ‖ temp(32) ‖ trust(16) = 80-d
PHI_COLS = C.RSSI_PHI + C.TEMP_PHI + C.TRUST_PHI


class FusionHead(nn.Module):
    """Linear(80→1)+σ. Weights split into the three named blocks for readability."""

    def __init__(self, in_dim=80):
        super().__init__()
        self.fc = nn.Linear(in_dim, 1)

    def forward(self, x):
        return torch.sigmoid(self.fc(x)).squeeze(-1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", default=DEF_CI)
    ap.add_argument("--out", default=DEF_OUT)
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--lr", type=float, default=1e-2)
    ap.add_argument("--wd", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"

    df = pd.read_parquet(args.context)
    missing = [c for c in PHI_COLS if c not in df.columns]
    if missing:
        raise SystemExit(f"c_i is missing φ columns: {missing[:5]}... "
                         "rebuild build_context_vector.py with all 3 detectors.")

    # mean-impute missing φ from the TRAIN split (φ already scaled → mean is neutral)
    tr_mask = df["split"].values == "train"
    fill = df.loc[tr_mask, PHI_COLS].mean()
    X = df[PHI_COLS].fillna(fill).values.astype(np.float32)
    y = df["is_sybil"].values.astype(np.float32)
    split = df["split"].values

    Xt = torch.tensor(X, device=dev)
    yt = torch.tensor(y, device=dev)
    idx = {s: torch.tensor(np.where(split == s)[0], device=dev)
           for s in ("train", "val", "test")}

    model = FusionHead(len(PHI_COLS)).to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.wd)
    # class-balanced BCE (train is ~30% sybil)
    pos = float(yt[idx["train"]].mean())
    pos_weight = torch.tensor([(1 - pos) / max(pos, 1e-6)], device=dev)
    lossf = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    def val_mcc():
        model.eval()
        with torch.no_grad():
            p = model(Xt[idx["val"]]).cpu().numpy()
        from sklearn.metrics import matthews_corrcoef
        yv = y[idx["val"].cpu().numpy()]
        return matthews_corrcoef(yv, (p >= 0.5).astype(int))

    best_mcc, best_state, wait = -1.0, None, 0
    for ep in range(args.epochs):
        model.train()
        opt.zero_grad()
        logits = model.fc(Xt[idx["train"]]).squeeze(-1)   # pre-sigmoid for BCEWithLogits
        loss = lossf(logits, yt[idx["train"]])
        loss.backward()
        opt.step()
        m = val_mcc()
        if m > best_mcc + 1e-4:
            best_mcc, best_state, wait = m, {k: v.clone() for k, v in model.state_dict().items()}, 0
        else:
            wait += 1
            if wait >= args.patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    print(f"Eq 3.18 head trained: best val-MCC={best_mcc:.4f} (epoch stop @ {ep})")

    # score EVERY window
    model.eval()
    with torch.no_grad():
        yhat = model(Xt).cpu().numpy()

    from sklearn.metrics import matthews_corrcoef
    for s in ("val", "test"):
        ii = idx[s].cpu().numpy()
        mcc = matthews_corrcoef(y[ii], (yhat[ii] >= 0.5).astype(int))
        print(f"  {s}: binary-MCC(ŷ_i @0.5) = {mcc:.4f}  (mean ŷ_i={yhat[ii].mean():.3f})")

    out = df[C.JOIN_KEY].copy()
    out["y_hat_i_fused"] = yhat
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    out.to_parquet(args.out, index=False)
    print(f"wrote {out.shape} -> {args.out}")


if __name__ == "__main__":
    main()

"""
refit_heads — re-fit the two frozen linear heads on current-distribution φ.

What is and is NOT refit
-----------------------
REFIT   the GRU's 7-class softmax head            Linear(32 -> 7)   [inside the .pt]
REFIT   the Eq 3.18 fusion head                   Linear(80 -> 1)+σ [fusion_head_weights]
FROZEN  the bi-GRU encoder, the RSSI CNN, the trust MLP, and every scaler.

The encoders are not the problem — a fresh probe on live φ_temp reaches MCC 0.906 while the
frozen softmax head reaches 0.000. Only the last layers are stale, so only they are refit.
The scalers are deliberately left alone: their zero/near-zero training variances are a real
and separate defect (packet_size var_=0, temp_id_change_flag scale_=0.00635 -> one pseudonym
change reads as z=157), but fixing them changes φ itself and would invalidate this refit.
Do that second, then re-run this.

Nothing is overwritten
----------------------
Outputs go to NEW paths; the July artifacts are untouched and additionally backed up under
ml/_prerefit_backup_20260805/ with SHA256SUMS.txt. Opt in per run:
    export SYBIL_GRU_MODEL_DIR=.../outputs/temporal_vehicle_tier_refit_<date>
    export SYBIL_FUSION_HEAD_WEIGHTS=.../outputs/fusion_head_weights_refit_<date>.json
Unset them to revert. Both loaders default to the July files.

Evaluation
----------
Split is by IDENTITY (run_id, claimed_node_id), 60/20/20, stratified per run, so no identity
appears in two splits — window-level splitting would leak, since one identity's overlapping
windows are near-duplicates. Old and new heads are scored on the SAME held-out test identities.

Run in ml/.venv:  python ml/refit/refit_heads.py
"""

import argparse
import json
import shutil
import sys
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import matthews_corrcoef, roc_auc_score

_HERE = Path(__file__).resolve().parent
_ML = _HERE.parent
sys.path.insert(0, str(_ML / "llm" / "common"))
import constants as C                                    # noqa: E402

KEY = ["run_id", "claimed_node_id", "window_start_seconds"]
GRU_SRC = _ML / "analyzers" / "temporal_gru" / "outputs" / "temporal_vehicle_tier"
FUSION_OUT = _ML / "fusion" / "outputs"
PHI_TEMP = [f"phi_temp_{i}" for i in range(32)]
PHI_ALL = C.RSSI_PHI + C.TEMP_PHI + C.TRUST_PHI          # Eq 3.18 concat order (80)


def identity_split(df, seed=42, fracs=(0.6, 0.2, 0.2)):
    """Assign whole identities to train/val/test, stratified within each run."""
    rng = np.random.default_rng(seed)
    split = pd.Series("train", index=df.index)
    for run, g in df.groupby("run_id"):
        ids = g["claimed_node_id"].unique()
        rng.shuffle(ids)
        n = len(ids)
        n_tr = int(round(fracs[0] * n))
        n_va = int(round(fracs[1] * n))
        assign = {}
        for i, cid in enumerate(ids):
            assign[cid] = "train" if i < n_tr else ("val" if i < n_tr + n_va else "test")
        split.loc[g.index] = g["claimed_node_id"].map(assign).values
    return split.values


def macro_mcc(y, p, classes):
    """Mean of per-class one-vs-rest MCC over classes PRESENT in y (undefined ones skipped)."""
    vals = []
    for k in classes:
        if (y == k).sum() == 0:
            continue
        vals.append(matthews_corrcoef((y == k).astype(int), (p == k).astype(int)))
    return float(np.mean(vals)) if vals else float("nan")


def fit_linear(Xtr, ytr, Xva, yva, out_dim, epochs, lr, wd, patience, seed, binary=False):
    """Full-batch AdamW on a single Linear layer, early-stopped on val MCC."""
    torch.manual_seed(seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    layer = nn.Linear(Xtr.shape[1], out_dim).to(dev)
    opt = torch.optim.AdamW(layer.parameters(), lr=lr, weight_decay=wd)

    Xt = torch.tensor(Xtr, dtype=torch.float32, device=dev)
    Xv = torch.tensor(Xva, dtype=torch.float32, device=dev)
    if binary:
        yt = torch.tensor(ytr, dtype=torch.float32, device=dev)
        pos = float(yt.mean())
        lossf = nn.BCEWithLogitsLoss(
            pos_weight=torch.tensor([(1 - pos) / max(pos, 1e-6)], device=dev))
    else:
        yt = torch.tensor(ytr, dtype=torch.long, device=dev)
        # inverse-frequency weights; classes with no support get weight 0 (never predicted)
        cnt = np.bincount(ytr, minlength=out_dim).astype(np.float64)
        w = np.divide(cnt.sum() / np.maximum(cnt, 1), out_dim, where=True)
        w[cnt == 0] = 0.0
        lossf = nn.CrossEntropyLoss(weight=torch.tensor(w, dtype=torch.float32, device=dev))

    best, best_state, wait = -2.0, None, 0
    for ep in range(epochs):
        layer.train()
        opt.zero_grad()
        logit = layer(Xt)
        loss = lossf(logit.squeeze(-1) if binary else logit, yt)
        loss.backward()
        opt.step()
        layer.eval()
        with torch.no_grad():
            lv = layer(Xv)
        pv = ((torch.sigmoid(lv.squeeze(-1)) >= 0.5).long() if binary
              else lv.argmax(1)).cpu().numpy()
        m = (matthews_corrcoef(yva, pv) if binary
             else macro_mcc(yva, pv, range(out_dim)))
        m = -1.0 if np.isnan(m) else m
        if m > best + 1e-4:
            best, wait = m, 0
            best_state = {k: v.clone() for k, v in layer.state_dict().items()}
        else:
            wait += 1
            if wait >= patience:
                break
    if best_state is not None:
        layer.load_state_dict(best_state)
    return layer, best, ep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phi", default=str(_HERE / "outputs" / "phi_current.parquet"))
    ap.add_argument("--epochs", type=int, default=3000)
    ap.add_argument("--lr", type=float, default=1e-2)
    ap.add_argument("--wd", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--tag", default=f"refit_{date.today():%Y%m%d}")
    args = ap.parse_args()

    df = pd.read_parquet(args.phi)
    df["split"] = identity_split(df, seed=args.seed)
    tr, va, te = (df.split == "train").values, (df.split == "val").values, (df.split == "test").values
    print(f"[refit] rows={len(df):,}  train/val/test = {tr.sum()}/{va.sum()}/{te.sum()}  "
          f"(identities {df.loc[tr,'claimed_node_id'].nunique()}/"
          f"{df.loc[va,'claimed_node_id'].nunique()}/{df.loc[te,'claimed_node_id'].nunique()})")

    y7 = df["attack_type"].to_numpy().astype(int)
    ybin = df["is_sybil"].to_numpy().astype(int)

    # ── 1. GRU softmax head: Linear(32 -> 7) on φ_temp ──────────────────────────
    Xt = df[PHI_TEMP].to_numpy(np.float32)
    head, val_mcc, ep = fit_linear(Xt[tr], y7[tr], Xt[va], y7[va], C.N_CLASSES,
                                   args.epochs, args.lr, args.wd, args.patience, args.seed)
    with torch.no_grad():
        dev = next(head.parameters()).device
        logit_new = head(torch.tensor(Xt, dtype=torch.float32, device=dev)).cpu().numpy()
    pred_new = logit_new.argmax(1)
    prob_new = np.exp(logit_new - logit_new.max(1, keepdims=True))
    prob_new /= prob_new.sum(1, keepdims=True)

    # OLD head, same test identities
    sd_old = torch.load(GRU_SRC / "temporal_federated_gru_hier.pt", map_location="cpu")
    W_old, b_old = sd_old["head.weight"].numpy(), sd_old["head.bias"].numpy()
    logit_old = Xt @ W_old.T + b_old
    pred_old = logit_old.argmax(1)
    prob_old = np.exp(logit_old - logit_old.max(1, keepdims=True))
    prob_old /= prob_old.sum(1, keepdims=True)

    print(f"\n[refit] GRU softmax head  (val macro-MCC {val_mcc:.4f}, stopped @ epoch {ep})")
    print(f"    {'metric':30s} {'OLD (July)':>12s} {'NEW (refit)':>12s}")
    rows = [
        ("binary MCC (pred != legitimate)",
         matthews_corrcoef(ybin[te], (pred_old[te] != 0).astype(int)),
         matthews_corrcoef(ybin[te], (pred_new[te] != 0).astype(int))),
        ("7-class macro-MCC",
         macro_mcc(y7[te], pred_old[te], range(C.N_CLASSES)),
         macro_mcc(y7[te], pred_new[te], range(C.N_CLASSES))),
        ("AUC of p_sybil = 1 - p_temp_0",
         roc_auc_score(ybin[te], 1 - prob_old[te, 0]),
         roc_auc_score(ybin[te], 1 - prob_new[te, 0])),
        ("mean p_temp_0 on LEGITIMATE",
         prob_old[te & (ybin == 0), 0].mean(), prob_new[te & (ybin == 0), 0].mean()),
        ("mean p_temp_0 on SYBIL",
         prob_old[te & (ybin == 1), 0].mean(), prob_new[te & (ybin == 1), 0].mean()),
    ]
    for name, o, n in rows:
        print(f"    {name:30s} {o:12.4f} {n:12.4f}")
    print("\n    per-class MCC on test (old -> new):")
    for k in range(C.N_CLASSES):
        if (y7[te] == k).sum() == 0:
            print(f"      {C.class_name(k):22s}   no test support (not learnable at this tier)")
            continue
        o = matthews_corrcoef((y7[te] == k).astype(int), (pred_old[te] == k).astype(int))
        n = matthews_corrcoef((y7[te] == k).astype(int), (pred_new[te] == k).astype(int))
        print(f"      {C.class_name(k):22s} {o:7.4f} -> {n:7.4f}   (n={int((y7[te]==k).sum())})")

    # ── 2. Eq 3.18 fusion head: Linear(80 -> 1)+σ on φ_rssi‖φ_temp‖φ_trust ───────
    for c in PHI_ALL:
        if c not in df.columns:
            df[c] = np.nan
    fill = df.loc[tr, PHI_ALL].mean()                     # train-split mean impute (as before)
    Xf = df[PHI_ALL].fillna(fill).to_numpy(np.float32)
    fh, fval, fep = fit_linear(Xf[tr], ybin[tr], Xf[va], ybin[va], 1,
                               args.epochs, args.lr, args.wd, args.patience, args.seed,
                               binary=True)
    with torch.no_grad():
        dev = next(fh.parameters()).device
        yhat_new = torch.sigmoid(
            fh(torch.tensor(Xf, dtype=torch.float32, device=dev)).squeeze(-1)).cpu().numpy()
    old = json.loads((FUSION_OUT / "fusion_head_weights.json").read_text())
    assert old["phi_cols"] == PHI_ALL, "fusion φ column order changed — refusing to compare"
    # expit, not 1/(1+exp(-z)): the old head puts some windows past z = -709, where the
    # naive form overflows to a hard 0.0 and creates artificial ties in the AUC.
    from scipy.special import expit
    yhat_old = expit(Xf @ np.asarray(old["weight"], np.float64) + old["bias"])

    print(f"\n[refit] Eq 3.18 fusion head  (val MCC {fval:.4f}, stopped @ epoch {fep})")
    print(f"    {'metric':30s} {'OLD (July)':>12s} {'NEW (refit)':>12s}")
    for name, o, n in [
            ("binary MCC (ŷ_i >= 0.5)",
             matthews_corrcoef(ybin[te], (yhat_old[te] >= 0.5).astype(int)),
             matthews_corrcoef(ybin[te], (yhat_new[te] >= 0.5).astype(int))),
            ("AUC of ŷ_i", roc_auc_score(ybin[te], yhat_old[te]),
             roc_auc_score(ybin[te], yhat_new[te])),
            ("mean ŷ_i on LEGITIMATE", yhat_old[te & (ybin == 0)].mean(),
             yhat_new[te & (ybin == 0)].mean()),
            ("mean ŷ_i on SYBIL", yhat_old[te & (ybin == 1)].mean(),
             yhat_new[te & (ybin == 1)].mean())]:
        print(f"    {name:30s} {o:12.4f} {n:12.4f}")

    # ── 3. export to NEW paths (July artifacts untouched) ───────────────────────
    dst = GRU_SRC.parent / f"temporal_vehicle_tier_{args.tag}"
    dst.mkdir(parents=True, exist_ok=True)
    for f in ("config.json", "scaler.pkl"):               # scaler deliberately unchanged
        shutil.copy2(GRU_SRC / f, dst / f)
    sd_new = dict(sd_old)
    sd_new["head.weight"] = head.weight.detach().cpu()
    sd_new["head.bias"] = head.bias.detach().cpu()
    torch.save(sd_new, dst / "temporal_federated_gru_hier.pt")
    cfg = json.loads((dst / "config.json").read_text())
    cfg["refit"] = {"date": str(date.today()), "what": "softmax head only; encoder frozen",
                    "source_model": str(GRU_SRC), "phi_dataset": args.phi,
                    "val_macro_mcc": float(val_mcc),
                    "test_binary_mcc": float(matthews_corrcoef(
                        ybin[te], (pred_new[te] != 0).astype(int))),
                    "test_macro_mcc": float(macro_mcc(y7[te], pred_new[te], range(C.N_CLASSES))),
                    "classes_without_support": [C.class_name(k) for k in range(C.N_CLASSES)
                                                if (y7 == k).sum() == 0]}
    (dst / "config.json").write_text(json.dumps(cfg, indent=2))

    fpath = FUSION_OUT / f"fusion_head_weights_{args.tag}.json"
    fpath.write_text(json.dumps({
        "phi_cols": PHI_ALL,
        "weight": fh.weight.detach().cpu().numpy().ravel().tolist(),
        "bias": float(fh.bias.detach().cpu().numpy().ravel()[0]),
        "impute_fill": {c: float(fill[c]) for c in PHI_ALL},
        "val_mcc": float(fval), "seed": args.seed,
        "refit": {"date": str(date.today()), "source": "fusion_head_weights.json",
                  "phi_dataset": args.phi},
    }, indent=2))

    print(f"\n[refit] wrote (July artifacts untouched):\n    {dst}\n    {fpath}")
    print("\n[refit] opt in for a run:")
    print(f"    export SYBIL_GRU_MODEL_DIR={dst}")
    print(f"    export SYBIL_FUSION_HEAD_WEIGHTS={fpath}")
    print("[refit] revert: unset both variables.")


if __name__ == "__main__":
    main()

"""Generate notebooks/vehicle_trust_score_model_v2.ipynb from the validated
trust_v2_lib. The notebook is a documented, interactive driver over the library
(single source of truth) so it can't drift from the tested code."""
import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()
cells = []
def md(s): cells.append(nbf.v4.new_markdown_cell(s.strip("\n")))
def co(s): cells.append(nbf.v4.new_code_cell(s.strip("\n")))

md(r"""
# Vehicle-Tier Trust Score Analyzer — **v2** (enriched · multi-percentage · paper-aligned)

A clean re-build of the vehicle-tier Trust Analyzer that fixes the v1 mismatches and produces a
**richer trust score for the full-mode LLM detector**, while keeping every thesis equation
(Eqs 3.3–3.5, 3.22–3.28) intact.

### What changed vs. v1
| v1 issue | v2 fix |
|---|---|
| Trained on the small `evaluation_runs/` v10–v40 sample (mismatch #4) | Trains on a real **attacker-percentage sweep**: `pct20` + `pct40` + `pct100` (true legitimate class) |
| Exported weights were the stale **8-feature** model | **26-feature** enriched vector; weights + φ_trust re-exported |
| No per-vehicle **score** exported (only weights) | Exports `vehicle_trust_scores_v2.csv` keyed to the pipeline contract |
| Only raw `rssi_dbm` | **RSSI verification** (`verification_state`, `mismatch_m`) — MISMATCH ≈ 98.6% sybil |
| No persistence signal | **Identity lifetime** (legit 6.5 s vs sybil 3.0 s) + beacon count |
| Trust used only local, correlated signals | **Cross-tier consensus** (RSU/controller) → independent reputation for `T_hist` |
| 5/6-class only, count-keyed | **7-class** `{0..6}`, windows keyed in **seconds** per the data contract |

The analytic `T_RSSI/T_behav/T_hist` keep their paper equations; the enrichment feeds (a) the MLP
feature vector that produces **φ_trust** (the deployed trust score the LLM reads) and (b) `T_hist`'s
reputation prior. No equation is rewritten.

> All heavy logic lives in the validated `ml/trust_v2/trust_v2_lib.py`; this notebook is a documented
> interactive driver over it.
""")

md("## 0. Setup — import the validated library")
co(r"""
import sys, time
from pathlib import Path
import numpy as np, pandas as pd
import matplotlib.pyplot as plt

LIB_DIR = Path.cwd().parent / "ml" / "trust_v2"      # notebooks/ -> ../ml/trust_v2
sys.path.insert(0, str(LIB_DIR))
import trust_v2_lib as T
print("datasets:")
for d in T.DATASETS:
    print("  ", d, "exists" if Path(d).exists() else "MISSING")
print(f"\n{len(T.FEATURE_COLS)} features:\n ", T.FEATURE_COLS)
print("\n7-class taxonomy:", T.CLASS_NAMES)
""")

md(r"""
## 1. Build (or load) the enriched windows

`build_pipeline` loads each run **one at a time** (memory-safe over the ~14 GB of logs), joins the
enriched RSSI-verification + RSU/controller consensus, labels 7-class, and aggregates to W=10-beacon
windows with the paper's trust components. Results are **cached to parquet** — the first run is slow
(reads the logs), every re-run is instant.

- `subsample_frac` keeps whole observer vehicles (whole FL clients). `0.05` = smoke, **`0.15–0.3`** for a real model.
- Delete `cache/windows.parquet` to force a rebuild at a different `frac`.
""")
co(r"""
CACHE = LIB_DIR / "cache" / "windows.parquet"
SUBSAMPLE_FRAC = 0.30          # fraction of observer vehicles (whole timelines). 0.05=quick smoke

t0 = time.time()
windows = T.build_pipeline(subsample_frac=SUBSAMPLE_FRAC, cache=str(CACHE))
print(f"\n{len(windows):,} windows in {time.time()-t0:.0f}s")
print("label (is_sybil):", windows["label"].value_counts().to_dict())
print("attack_type {0..6}:", dict(sorted(windows["attack_type"].value_counts().items())))
print("by attacker %:", windows.groupby('attack_percentage')['label'].agg(['size','mean']).round(3).to_dict())
windows.head(3)
""")

md("## 2. EDA — do the enriched signals separate the classes?")
co(r"""
fig, ax = plt.subplots(1, 3, figsize=(16, 4))
for a, col, title in zip(ax,
        ["identity_lifetime", "rssi_mismatch_frac", "T_composite"],
        ["Identity lifetime (s)", "RSSI mismatch fraction", "T_composite (paper Eq 3.22)"]):
    for lab, name in [(0, "legit"), (1, "sybil")]:
        a.hist(windows.loc[windows.label == lab, col].dropna(), bins=40, alpha=0.5,
               density=True, label=name)
    a.set_title(title); a.legend()
plt.tight_layout(); plt.show()

print("Per-attack-type positive rate (7-class):")
print(windows.groupby("attack_type")["label"].agg(["size", "mean"]).round(3))
""")

md(r"""
## 3. Split, impute, standardize

Group-stratified 70/15/15 by `(run_id, ground-truth vehicle)` within each `(attacker%, attack_type)`
stratum — no vehicle leaks across train/val/test. Train-only median-impute + standardization; the
stats are exported so C++/inference standardizes identically.
""")
co(r"""
windows = T.group_stratified_split(windows)
windows, STATS = T.prep_features(windows)
print("split:", windows["split"].value_counts().to_dict())
tr, va, te = [windows[windows.split == s] for s in ("train", "val", "test")]
NF = len(T.FEATURE_COLS)
print(f"features={NF}  train={len(tr):,} val={len(va):,} test={len(te):,}")
""")

md(r"""
## 4. Train — centralized warm-start → hierarchical FL

The MLP is `Linear(26,32)→ReLU→Drop→Linear(32,16)→ReLU→Linear(16,1)`; the **16-dim penultimate
activation is φ_trust** — the deployed trust score. Training: a short centralized warm-start, then
hierarchical FedProx FL (per-OBU clients → RSU size-weighted avg → SDN trimmed-mean, + DP noise,
Eqs 3.26–3.28), class-weighted and stratified-sampled, early-stopped on val-MCC.
""")
co(r"""
pos_rate = tr["label"].mean()
POS_WEIGHT = float(np.clip((1 - pos_rate) / max(pos_rate, 1e-6), 1.0, 20.0))
HP = dict(dropout=0.1, fedprox_mu=0.001, dp_sigma=0.02, local_lr=0.05,
          batch_size=32, local_epochs=2, trim_k=1)

warm = T.centralized_pretrain(tr, T.FEATURE_COLS, NF, epochs=3, pos_weight=POS_WEIGHT)
wm, _, _ = T.evaluate_state(warm, va, T.FEATURE_COLS, NF)
print(f"warm-start val MCC = {wm['mcc']:.4f}")

state, history, best = T.train_fl(tr, va, T.FEATURE_COLS, HP, NF, max_rounds=40,
                                  pos_weight=POS_WEIGHT, warm_start=warm)
print(f"\nbest val MCC = {best:.4f}")
""")

md("### FL convergence")
co(r"""
plt.figure(figsize=(8, 4))
plt.plot(history["round"], history["val_mcc"], marker="o")
plt.axhline(best, ls="--", c="grey", label=f"best={best:.3f}")
plt.xlabel("FL round"); plt.ylabel("val MCC"); plt.title("Hierarchical FL convergence"); plt.legend()
plt.tight_layout(); plt.show()
""")

md("## 5. Test-set evaluation")
co(r"""
from sklearn.metrics import classification_report, confusion_matrix
tm, probs, phi = T.evaluate_state(state, te, T.FEATURE_COLS, NF)
print("TEST:", {k: round(v, 4) for k, v in tm.items()})
pred = (probs >= 0.5).astype(int)
print("\n", classification_report(te["label"], pred, target_names=["legit", "sybil"], zero_division=0))
print("confusion:\n", confusion_matrix(te["label"], pred))
""")

md(r"""
## 5b. Intensity-robustness — **evaluation only** (honest use of `active_attack_pct`)

`active_attack_pct` (the 20→100 ladder) is **NOT a model feature** — a real vehicle cannot observe the
attack density, so feeding it would be oracle leakage. It is kept purely as **metadata** to *stratify the
evaluation*: how does detection hold up as attack intensity rises? The model stays blind to it.
""")
co(r"""
te_eval = te.copy(); te_eval["pred"] = pred
from sklearn.metrics import matthews_corrcoef
def _mcc(g):
    return matthews_corrcoef(g["label"], g["pred"]) if g["label"].nunique() > 1 else np.nan
by_intensity = te_eval.groupby("active_attack_pct").apply(_mcc).rename("test_mcc")
by_static    = te_eval.groupby("attack_percentage").apply(_mcc).rename("test_mcc")
print("MCC by intensity ladder (active_attack_pct):\n", by_intensity.round(3))
print("\nMCC by run attacker % (attack_percentage):\n", by_static.round(3))
fig, ax = plt.subplots(1, 2, figsize=(13, 4))
by_intensity.plot(marker="o", ax=ax[0], title="Detection vs active-attacker % (intensity ladder)")
by_static.plot(marker="s", ax=ax[1], title="Detection vs run attacker % (static pool)")
for a in ax: a.set_ylabel("test MCC"); a.grid(True)
plt.tight_layout(); plt.show()
""")

md(r"""
## 6. Export for the full-mode LLM detector

- `vehicle_trust_scores_v2.csv` — one row per window, keyed **`(claimed_node_id, window_start_seconds, split)`**,
  with `attack_type∈{0..6}`, `is_sybil`, the `T_*` components, **`phi_trust_0..15`**, and the interpretable
  enriched fields (`rssi_mismatch_frac`, `identity_lifetime`, `rsu_report_count`, `ctrl_trust`, …) that give
  the LLM type-bearing evidence to reason over.
- `vehicle_trust_mlp_v2.json` — weights + standardization stats + hyperparameters.
""")
co(r"""
OUT = LIB_DIR / "outputs"
scores = T.export_scores(windows, state, T.FEATURE_COLS, OUT / "vehicle_trust_scores_v2.csv")
T.export_weights_json(state, T.FEATURE_COLS, STATS, {**T.DEFAULT_HP, **HP}, OUT / "vehicle_trust_mlp_v2.json")
print(f"exported {len(scores):,} scored windows -> {OUT}")
print("columns:", list(scores.columns)[:14], "... +phi_trust_0..15")
scores[["claimed_node_id","window_start_seconds","split","attack_type","is_sybil",
        "phi_trust_score","T_composite","identity_lifetime","rssi_mismatch_frac"]].head()
""")

md(r"""
## 7. Ablation — which enrichment matters?

Retrains (centralized, fast) with each enriched block dropped, to show the trust score genuinely
leans on the new signals (RSSI-verification / persistence / consensus), not just the v1 features.
""")
co(r"""
BLOCKS = {
    "full": [],
    "-rssi_verify": ["rssi_mismatch_frac", "mismatch_m_mean"],
    "-persistence": ["identity_lifetime", "beacon_count_mean"],
    "-consensus":   ["rsu_observer_count","rsu_report_count","rsu_verified_prob",
                     "rsu_false_decision","ctrl_trust","ctrl_observer_count"],
}
rows = []
for name, drop in BLOCKS.items():
    cols = [c for c in T.FEATURE_COLS if c not in drop]
    st = T.centralized_pretrain(tr, cols, len(cols), epochs=4, pos_weight=POS_WEIGHT)
    m, _, _ = T.evaluate_state(st, te, cols, len(cols))
    rows.append({"config": name, "n_feat": len(cols), "test_mcc": round(m["mcc"], 4),
                 "test_f1": round(m["f1"], 4)})
pd.DataFrame(rows)
""")

md(r"""
## 8. Summary

**v2 delivers**, on the pct20+pct40+pct100 sweep: a 7-class-aligned, seconds-keyed vehicle-tier trust
analyzer whose enriched **φ_trust** and interpretable `T_*` + signature fields feed the full-mode LLM.
Every thesis equation is preserved; the enrichment is in the observable inputs and the exported
evidence, not the math.

**Feeds the fusion** via `vehicle_trust_scores_v2.csv` → join into `ml/fullmode/build_evidence.py`
(key: `claimed_node_id`, `window_start_seconds`).

**Retrain manually:** `PYTHONUNBUFFERED=1 ml/.venv/bin/python ml/trust_v2/trust_v2_lib.py --train --frac 0.15 --rounds 40`
(auto-uses the cache after the first build).
""")

nb["cells"] = cells
nb["metadata"] = {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                  "language_info": {"name": "python"}}
out = Path(__file__).resolve().parents[2] / "notebooks" / "vehicle_trust_score_model_v2.ipynb"
nbf.write(nb, str(out))
print("wrote", out, "with", len(cells), "cells")

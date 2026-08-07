"""
type_tokens — can any observable token tell the ATTACK TYPES apart?

Context
-------
7-class attribution is stuck ~0.42 and collapses to "outsider". Measured cause
(llm-prompt-tokens-uninformative): of the scalars in the LLM prompt only trust.p_sybil
discriminates (AUC 0.989), and it is a BINARY sybil-ness score. Nothing in the prompt
encodes WHICH attack it is, so the agents cannot attribute a type — they can only say
sybil/not and fall back on a modal label. Fixing the GRU cannot help (proven by the in-sim
A/B: flipping its token left the verdict outsider 359/359).

So the question is not "which model" but "does the SIGNAL exist in the logs at all".

This script:
  1. scores the EXISTING evidence tokens per type (one-vs-rest AUC), and
  2. builds candidate type-encoding features from the comm log and scores them the same way,
  3. then fits a small multinomial model to get an achievable 7-class MCC ceiling.

Every candidate is LIVE-OBSERVABLE — computed from what a receiver can see. In particular
none of them read real_node_id, and none read the VALUE of claimed_node_id (Sybil ids are
numbered >= N_Vehicles, so the id itself is a label leak; it is used only as a grouping key).

Attack-type signatures being targeted
  outsider (1) foreign identity, no registration/RSU corroboration
  sim      (2) ONE node emitting MANY pseudonyms AT ONCE -> many identities share a position
  nonsim   (3) sequential pseudonym cycling -> short identity lifetime, few beacons, handoffs
  indirect (4) anomaly relayed via a compromised node -> observer/position inconsistency

Run in ml/.venv:  python ml/refit/type_tokens.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
_ML = _HERE.parent
sys.path.insert(0, str(_ML / "analyzers" / "temporal_gru"))
sys.path.insert(0, str(_ML / "fusion"))
import identity_manifest as IDM                          # noqa: E402
import predict as P                                      # noqa: E402

KEY = ["run_id", "claimed_node_id", "window_start_seconds"]
COHORT_RADIUS_M = 50.0          # "same place" for the sim cohort test
USE = {"receive_time", "flow", "receiver_role", "receiver_id", "claimed_node_id",
       "bsm_temporary_id", "bsm_msg_count", "bsm_x", "bsm_y", "bsm_speed", "attack_type"}


def candidate_tokens(run_dir, run_id):
    """Live-observable per-(claimed_id, 2 s cell) features aimed at attack TYPE."""
    df = pd.read_csv(Path(run_dir) / "communication_log.csv",
                     usecols=lambda c: c in USE)
    df = df[(df["flow"] == "v2v_beacon") & (df["receiver_role"] == "vehicle")].copy()
    if df.empty:
        return pd.DataFrame()
    df["run_id"] = run_id
    df["w"] = IDM.snap_grid(df["receive_time"].to_numpy())

    # first time each identity was seen anywhere in the run (causal within the run)
    first_seen = df.groupby("claimed_node_id")["receive_time"].min().rename("t_first")
    df = df.join(first_seen, on="claimed_node_id")

    g = df.groupby(["run_id", "claimed_node_id", "w"])
    out = g.agg(
        n_beacons=("receive_time", "size"),
        n_observers=("receiver_id", "nunique"),
        temp_id_nunique=("bsm_temporary_id", "nunique"),
        speed_std=("bsm_speed", "std"),
        x=("bsm_x", "mean"), y=("bsm_y", "mean"),
        t_first=("t_first", "min"), t_max=("receive_time", "max"),
        msg_min=("bsm_msg_count", "min"), msg_max=("bsm_msg_count", "max"),
    ).reset_index()

    # nonsim signature: how long has this identity existed by the end of this cell
    out["identity_age_s"] = out["t_max"] - out["t_first"]
    # pseudonym churn per beacon (rotation rate)
    out["temp_id_rate"] = out["temp_id_nunique"] / out["n_beacons"].clip(lower=1)
    # identity reuse: msg counter spans a wide range in one 2 s cell
    out["msg_span"] = out["msg_max"] - out["msg_min"]
    out["speed_std"] = out["speed_std"].fillna(0.0)

    # sim signature: how many OTHER identities report from within COHORT_RADIUS_M
    # in the same 2 s cell. One physical node emitting many pseudonyms puts them all
    # at (nearly) one point, which no honest set of distinct vehicles does.
    coh = []
    for (_, w), grp in out.groupby(["run_id", "w"]):
        pts = grp[["x", "y"]].to_numpy()
        if len(pts) == 1:
            coh.append(pd.Series([0], index=grp.index))
            continue
        d = np.linalg.norm(pts[:, None, :] - pts[None, :, :], axis=-1)
        coh.append(pd.Series((d <= COHORT_RADIUS_M).sum(1) - 1, index=grp.index))
    out["cohort_size"] = pd.concat(coh).reindex(out.index).fillna(0).astype(int)
    # density-normalised: cohort relative to the cell's median, so a busy junction that
    # legitimately holds many vehicles does not read as a Sybil cluster
    med = out.groupby(["run_id", "w"])["cohort_size"].transform("median")
    out["cohort_excess"] = out["cohort_size"] - med

    out = out.rename(columns={"w": "window_start_seconds"})
    keep = KEY + ["n_beacons", "n_observers", "temp_id_nunique", "temp_id_rate",
                  "identity_age_s", "msg_span", "speed_std", "cohort_size", "cohort_excess"]
    return out[keep]


def ovr_auc(y, s, k):
    """One-vs-rest AUC of score s for class k, orientation-free (max(a, 1-a))."""
    from sklearn.metrics import roc_auc_score
    m = np.isfinite(s)
    yy = (y[m] == k).astype(int)
    if yy.sum() == 0 or yy.sum() == len(yy) or np.unique(s[m]).size < 2:
        return np.nan
    a = roc_auc_score(yy, s[m])
    return max(a, 1 - a)


def main():
    sys.path.insert(0, str(_HERE))
    import build_phi_dataset as B

    base = pd.read_parquet(_HERE / "outputs" / "phi_current.parquet")
    frames = []
    for rel, at in B.DEF_RUNS:
        run_dir = _ML.parent / rel
        if not (run_dir / "communication_log.csv").exists():
            continue
        t = candidate_tokens(run_dir, rel.replace("/", "__"))
        if not t.empty:
            frames.append(t)
            print(f"  tokens built: {rel:52s} {len(t):6d} rows")
    cand = pd.concat(frames, ignore_index=True)
    df = base.merge(cand, on=KEY, how="left")
    y = df["attack_type"].to_numpy().astype(int)
    print(f"\nmerged: {len(df)} windows   class counts {pd.Series(y).value_counts().sort_index().to_dict()}")

    names = {0: "legit", 1: "outsider", 2: "sim", 3: "nonsim", 4: "indirect"}
    present = [k for k in sorted(set(y)) if k in names]

    existing = ["phi_trust_score", "y_hat_i", "T_composite", "T_RSSI", "T_behav", "T_hist",
                "rssi_mismatch_frac", "identity_lifetime", "rsu_report_count",
                "rsu_verified_prob", "ctrl_trust"]
    new = ["n_beacons", "n_observers", "temp_id_nunique", "temp_id_rate",
           "identity_age_s", "msg_span", "speed_std", "cohort_size", "cohort_excess"]

    for title, cols in (("EXISTING evidence tokens", existing), ("CANDIDATE type tokens", new)):
        print(f"\n{title} — one-vs-rest AUC per class (>=0.70 is usable)")
        hdr = "  " + f"{'token':22s}" + "".join(f"{names[k]:>10s}" for k in present)
        print(hdr)
        for c in cols:
            if c not in df.columns:
                print(f"  {c:22s}{'ABSENT':>10s}")
                continue
            s = pd.to_numeric(df[c], errors="coerce").to_numpy(dtype=float)
            row = "".join(f"{ovr_auc(y, s, k):10.3f}" if np.isfinite(ovr_auc(y, s, k))
                          else f"{'-':>10s}" for k in present)
            print(f"  {c:22s}{row}")

    # achievable ceiling: multinomial model, grouped CV by identity
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import cross_val_predict, GroupKFold
    from sklearn.metrics import matthews_corrcoef
    print("\nachievable 7-class ceiling (HistGradientBoosting, GroupKFold-5 by identity):")

    def macro(yy, pp):
        v = [matthews_corrcoef((yy == k).astype(int), (pp == k).astype(int))
             for k in np.unique(yy)]
        return float(np.mean(v))

    for label, cols in (("existing tokens only", existing),
                        ("candidate tokens only", new),
                        ("existing + candidates", existing + new)):
        cc = [c for c in cols if c in df.columns]
        X = df[cc].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
        pred = cross_val_predict(HistGradientBoostingClassifier(max_iter=200, random_state=0),
                                 X, y, cv=GroupKFold(5), groups=df["claimed_node_id"])
        print(f"  {label:24s} macro-MCC = {macro(y, pred):.4f}   "
              f"(vs in-sim LLM 7-class 0.4170–0.4281)")


if __name__ == "__main__":
    main()

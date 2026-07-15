"""
Build the per-window context table cᵢ (Eq 3.31) for the single-head LLM detector.

ALIGNED to the v2/v3 vehicle-tier detector contract (replaces the stale
build_evidence.py, which read retired seq6_full_s1 CSVs on a bare claimed_id key):

  temporal_vehicle_tier.parquet   phi_temp_0..31, p_temp_0..6   (GRU v4)  [REQUIRED]
  rssi_vehicle_tier.parquet       phi_rssi_0..31, y_hat_i       (RSSI v3) [optional]
  trust_vehicle_tier.parquet      phi_trust_0..15, phi_trust_score, T_composite (+subfields) [optional]

All join on the exact run-scoped key JOIN_KEY. Extra Eq 3.31 token groups
(mobility {v_rel, ρ_c, Δt_sync}, signatures S1..S6, ensemble ŷ_ens) are joined
here too IF their parquet exists — every one is optional/nullable, so cᵢ builds
now (temporal-only) and enriches as each source lands. 7-class throughout.

Runs in ml/.venv (pandas/pyarrow). Output: ml/fullmode/context/c_i.parquet
"""

import argparse
import os

import pandas as pd

import constants as C

_HERE = os.path.dirname(os.path.abspath(__file__))
DEF_OUT = C.C_I_PARQUET         # canonical cᵢ path (constants hub)

# optional Eq 3.31 enrichment sources (not built yet — nullable when absent)
MOBILITY_PARQUET = os.path.join(C.OUTPUTS_DIR, "mobility_tokens.parquet")   # v_rel, rho_c, dt_sync
SIGNATURE_PARQUET = os.path.join(C.OUTPUTS_DIR, "signatures_s16.parquet")   # s1..s6
ENSEMBLE_PARQUET = os.path.join(C.OUTPUTS_DIR, "ensemble_yhat.parquet")     # y_hat_ens


def _load(path, label):
    if not os.path.exists(path):
        print(f"  [skip] {label}: not found ({os.path.basename(path)})")
        return None
    df = pd.read_parquet(path)
    # Contract guard: run_id MUST be the clean pctNN_s1 (never a per-type virtual
    # id like pctNN_s1_type3). The trust notebook derives windows on a per-type
    # run_id; if that leaks into the export it silently 0-joins the spine. Strip
    # any trailing _type<N> here so a violation can't wedge the fusion again.
    if "run_id" in df.columns:
        cleaned = df["run_id"].astype(str).str.replace(r"_type\d+$", "", regex=True)
        if (cleaned != df["run_id"].astype(str)).any():
            print(f"         [normalize] stripped _type<N> from {label} run_id")
            df = df.copy()
            df["run_id"] = cleaned
    print(f"  [ok]   {label}: {df.shape[0]:,} rows, {df.shape[1]} cols")
    return df


def _feature_cols(df, present_key):
    """non-key, non-label columns a source contributes (deduped against the spine)."""
    drop = set(C.JOIN_KEY) | set(C.LABEL_COLS) | {"active_attack_pct"} | present_key
    return [c for c in df.columns if c not in drop]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--temporal", default=C.TEMPORAL_PARQUET)
    ap.add_argument("--rssi", default=C.RSSI_PARQUET)
    ap.add_argument("--trust", default=C.TRUST_PARQUET)
    ap.add_argument("--mobility", default=MOBILITY_PARQUET)
    ap.add_argument("--signatures", default=SIGNATURE_PARQUET)
    ap.add_argument("--ensemble", default=ENSEMBLE_PARQUET)
    ap.add_argument("--out", default=DEF_OUT)
    args = ap.parse_args()

    print("Loading detector exports (run-scoped key = %s):" % C.JOIN_KEY)
    temporal = _load(args.temporal, "temporal (GRU v4)")
    if temporal is None:
        raise SystemExit(f"REQUIRED spine missing: {args.temporal}\n"
                         "  Run temporal_gru_seq_v3.ipynb first.")

    # spine = temporal windows; it carries the 7-class label + split per window.
    ev = temporal.copy()
    present = set(ev.columns)
    n = len(ev)

    for path, label in [(args.rssi, "rssi (CNN v3)"),
                        (args.trust, "trust (v2)"),
                        (args.mobility, "mobility tokens"),
                        (args.signatures, "signatures S1..S6"),
                        (args.ensemble, "ensemble ŷ_ens")]:
        df = _load(path, label)
        if df is None:
            continue
        cols = _feature_cols(df, present)
        if not cols:
            print(f"         (no new columns from {label})")
            continue
        keep = [k for k in C.JOIN_KEY if k in df.columns] + cols
        ev = ev.merge(df[keep], on=[k for k in C.JOIN_KEY if k in df.columns], how="left")
        present |= set(cols)

    # ── coverage report (per detector = fraction of spine windows joined) ──
    print(f"\nspine windows: {n:,} | identities: {ev['claimed_node_id'].nunique():,} "
          f"| runs: {sorted(ev['run_id'].astype(str).unique().tolist())}")
    print(f"split: {ev['split'].value_counts().to_dict()}")
    print(f"attack_type (7-class): "
          f"{ {C.class_name(k): int(v) for k, v in ev['attack_type'].value_counts().sort_index().items()} }")
    for grp, probe in [("rssi φ", "phi_rssi_0"), ("trust φ", "phi_trust_0"),
                       ("mobility", "v_rel"), ("signatures", "s1"), ("ŷ_ens", "y_hat_ens")]:
        if probe in ev.columns:
            cov = ev[probe].notna().sum()
            print(f"  coverage {grp:10s}: {cov:,}/{n:,} ({100*cov/n:.1f}%)")
        else:
            print(f"  coverage {grp:10s}: absent (source not built)")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    ev.to_parquet(args.out, index=False)
    print(f"\nwrote cᵢ table: {ev.shape} -> {args.out}")


if __name__ == "__main__":
    main()

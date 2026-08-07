"""d4_rsu_union — D4-ONLY repair of the RSU-tier evidence path. DEFAULT OFF.

WHY THIS EXISTS
    `build_context_live.assemble_ci` is GRU-anchored: cᵢ has one row per window per
    identity THE GRU EMITTED, and the RSU-tier XGB outputs are LEFT-joined onto it. The
    two tiers do not agree on the identity population — measured on the D4 v3 run,
    the GRU emitted 633 identities, the temporal XGB 256, and only 72 were common. The
    window grids align perfectly (10/10 window_start values match), so this is an
    identity-set mismatch, not a time-grid one.

    Consequence: 72 % of everything the temporal XGB scores is discarded at the join,
    and on v3 only 5 % of Sybil rows carry a p̄_temp at all. Where the term is absent
    Eq 3.20 (`ensemble_live._weighted_score`) renormalises λ over the terms present, so
    those rows silently collapse to the vehicle-tier score and D4 becomes D3.

    That matters because the discarded stream is the strongest signal in the stack:
    live AUC 0.998 (v3) / 1.000 (v1), matching its 0.966 offline test MCC.

WHAT IT DOES
    Adds the RSU-tier-only rows back as ADDITIONAL cᵢ rows: for every (run_id,
    claimed_node_id, window_start_seconds) the XGBs scored but the GRU never anchored,
    emit a row whose ŷ_ens is Eq 3.20 over the RSU terms alone (ŷ_i stays NaN and
    renormalises out — the nullable-graceful path that is already the contract).

    It is purely ADDITIVE. Rows that already exist are returned untouched and
    bit-identical, so the vehicle-tier decision for every identity the GRU saw is
    exactly what it was. The Eq 3.18 head is NEVER applied to the new rows: they have no
    live φ, and imputing one would fabricate a vehicle-tier opinion out of train-split
    means.

SCOPE — READ BEFORE ENABLING
    Gated on the SYBIL_D4_RSU_UNION env var, unset everywhere except
    mock_ablation/D4_refit/run_d4.sh. With it unset this module is imported but does
    nothing, and the daemon's behaviour is byte-identical to before it existed — that
    is the property the full-system runs depend on and it is asserted by
    mock_ablation/D4_refit/verify_no_fullmode_change.py.

    This is a D4 ablation instrument, NOT a full-mode fix. The real fix is to stop
    anchoring cᵢ on the GRU at all, which changes every rung and the LLM tier's input
    population, and must not be smuggled in through an ablation.

CAVEAT FOR THE WRITE-UP
    Unioning changes the identity POPULATION that reaches scoring, not just the score
    of a fixed population. Report D4 both ways — over all identities and over the
    D3-common subset — or the comparison silently mixes a detection gain with a
    denominator change. score_d4.py --common-with does the second one.
"""
import os

import numpy as np
import pandas as pd

FLAG = "SYBIL_D4_RSU_UNION"
LAMBDA_ENV = "SYBIL_D4_LAMBDAS"
KEY = ["run_id", "claimed_node_id", "window_start_seconds"]


def enabled():
    return os.environ.get(FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def lambdas_override():
    """Eq 3.20 λ for the D4 condition only. None => the deployed ensemble_lambdas.json.

    λ is a declared hyperparameter of Eq 3.20, and D4 is the 'tuned-lambda' condition,
    so re-selecting it here is in scope. Select it on the pass-1 evidence and report
    pass 2 — the same two-pass discipline the τ sweep already uses. Anything else is
    tuning on the reported run.
    """
    raw = os.environ.get(LAMBDA_ENV, "").strip()
    if not raw:
        return None
    lam = [float(x) for x in raw.replace(",", " ").split()]
    if len(lam) != 3:
        raise ValueError(f"{LAMBDA_ENV} must be 3 comma-separated floats "
                         f"(λ over [ŷ_i, p̄_temp, p̄_rssi]), got {raw!r}")
    if not any(lam):
        raise ValueError(f"{LAMBDA_ENV} cannot be all zero — Eq 3.20 would be undefined")
    return lam


def union(ci, pbar_frames, lam=None):
    """Append RSU-tier-only rows to an already-enriched cᵢ frame.

    ci           the frame straight out of ensemble_live.enrich (has y_hat_ens)
    pbar_frames  the list of RSU-tier keyed frames the daemon built (p̄_temp, p̄_rssi)
    lam          Eq 3.20 λ; None => deployed default
    """
    if not enabled() or not pbar_frames:
        return ci

    rsu = None
    for f in pbar_frames:
        if f is None or not len(f):
            continue
        rsu = f.copy() if rsu is None else rsu.merge(f, on=KEY, how="outer")
    if rsu is None or not len(rsu):
        return ci

    # Only rows with NO anchor at all. An anchored row keeps whatever the left join gave
    # it, including a missing p̄ — overwriting those would change the vehicle tier's
    # existing decisions, which this module promises not to do.
    if len(ci):
        have = ci[KEY].copy()
        have["_anchored"] = True
        rsu = rsu.merge(have, on=KEY, how="left")
        rsu = rsu[rsu["_anchored"].isna()].drop(columns=["_anchored"])
    if not len(rsu):
        return ci

    # ŷ_i is genuinely absent for these rows: no live φ, so no Eq 3.18 opinion.
    #
    # These rows are scored on p̄_temp ALONE, not on renormalised λ over both RSU terms.
    # Renormalising lets p̄_rssi carry the row, and p̄_rssi is saturated live (measured
    # mean 0.997 on Sybil rows vs 0.860 on legit, live AUC 0.65-0.74 against its 0.837
    # offline MCC) — it pins an unanchored row near 1.0 whatever the label, so the
    # single τ that serves the anchored population turns those rows into false
    # positives. Measured on pass 1: shared-λ union -0.008 mean MCC, p̄_temp-only union
    # +0.012. p̄_temp is the stream with live AUC 0.998, and it shares a scale with the
    # anchored rows, so one τ still serves both populations.
    #
    # A row the temporal XGB never scored has no trustworthy evidence at all and is
    # dropped rather than decided on p̄_rssi alone.
    if "p_bar_temp" not in rsu.columns:
        return ci
    rsu = rsu[rsu["p_bar_temp"].notna()].copy()
    if not len(rsu):
        return ci
    rsu["y_hat_i_fused"] = np.nan
    rsu["y_hat_ens"] = pd.to_numeric(rsu["p_bar_temp"], errors="coerce").astype(float)
    rsu["rsu_only"] = True

    ci = ci.copy()
    ci["rsu_only"] = False
    out = pd.concat([ci, rsu], ignore_index=True, sort=False)
    return out.sort_values(["window_start_seconds", "claimed_node_id"]).reset_index(drop=True)

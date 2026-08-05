"""
build_context_live — assemble ONE live cᵢ (Eq 3.31) from the analyzer predictors,
the real-time twin of ml/llm/common/build_context_vector.py.

Sync policy (decided 2026-07-16, matches build_context_vector's join semantics):
  * GRU (temporal) is the REQUIRED anchor — its 2 s-grid windows are the cᵢ rows;
  * trust / rssi / ŷ_ens / mobility are OPTIONAL, joined `how="left"` on the live key
    KEY = (run_id, claimed_node_id, window_start_seconds) — absent -> null (build_context
    is null-safe, so partial coverage never drops a row);
  * default join is EXACT-key (reproduces the offline cᵢ the LLM trained on). Optional
    carry_forward=True does an as-of backward join so a slower analyzer's most-recent
    <= t value fills a cell (better live coverage; a deliberate deviation from training).

No labels / split / attack_percentage are needed — build_context reads only features +
the three identifiers. Output is a DataFrame whose rows feed build_llm_dataset.build_context.
"""

import os
import sys

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
KEY = ["run_id", "claimed_node_id", "window_start_seconds"]


def _asof_join(left, right, tol):
    """Backward as-of join: carry each right row forward to left cells with a >= time,
    per (run_id, claimed_node_id). `tol` (seconds) bounds how stale a value may be."""
    l = left.sort_values("window_start_seconds")
    r = right.sort_values("window_start_seconds")
    return pd.merge_asof(l, r, on="window_start_seconds",
                         by=["run_id", "claimed_node_id"],
                         direction="backward", tolerance=tol)


def assemble_ci(temporal, rssi=None, trust=None, ensemble=None, mobility=None,
                extra=None, carry_forward=False, tol=None):
    """GRU-anchored assembly of the three (+optional) predictor outputs into cᵢ.

    Each arg is a DataFrame keyed by KEY (as the predictors emit). `temporal` is
    required (the anchor). `extra` is a list of additional keyed sources (e.g. the
    RSU-tier XGB p̄ outputs). Returns the cᵢ DataFrame (one row per anchored 2 s cell).
    """
    if temporal is None or len(temporal) == 0:
        return pd.DataFrame()
    ev = temporal.copy()
    sources = [(rssi, "rssi"), (trust, "trust"), (ensemble, "ensemble"), (mobility, "mobility")]
    sources += [(df, "extra") for df in (extra or [])]
    for df, name in sources:
        if df is None or len(df) == 0:
            continue
        new = [c for c in df.columns if c not in KEY and c not in ev.columns]
        if not new:
            continue
        right = df[KEY + new]
        ev = _asof_join(ev, right, tol) if carry_forward else \
            ev.merge(right, on=KEY, how="left")
    return ev.reset_index(drop=True)


def build_messages(ci_df, gate_degenerate_temporal=True):
    """cᵢ DataFrame -> list of {key..., context} using the shared build_context.

    context is the Eq 3.31 token dict the 3 agents consume (identical across agents;
    each agent only prepends its own role system prompt).

    gate_degenerate_temporal — when the GRU flagged itself degenerate for this batch
    (`temporal_degenerate`), blank p_temp_* so build_context omits the whole
    `features.temporal` group. _num() maps NaN to None and _present() drops such
    columns, so the tokens simply do not appear.

    The point is that MISSING evidence and WRONG evidence are not the same thing to a
    language model. Measured 2026-08-05: with the GRU unable to emit "legitimate" for
    any of 1636 windows, its modal class was `outsider`, and the LLM copied that onto
    340 of 347 true insider-simultaneous identities — 7-class MCC 0.4579 while the
    binary MCC was 0.93. Withholding a class label the analyzer cannot support lets
    the model fall back on the trust and ensemble evidence, which are healthy.

    Only the LLM PROMPT is affected. phi_temp still anchors cᵢ and still feeds the
    Eq 3.18/3.20 fusion head, so ŷ_ens and the binary decision path are untouched.
    Pass False to A/B the gate.
    """
    sys.path.insert(0, os.path.join(_HERE, "..", "llm", "common"))
    import build_llm_dataset as B          # noqa: E402  (build_context, null-safe)

    gated = 0
    if gate_degenerate_temporal and "temporal_degenerate" in ci_df.columns:
        mask = ci_df["temporal_degenerate"].fillna(0).astype(int) == 1
        if mask.any():
            ci_df = ci_df.copy()
            pcols = [c for c in ci_df.columns if c.startswith("p_temp_")]
            ci_df.loc[mask, pcols] = float("nan")
            gated = int(mask.sum())

    out = []
    for _, row in ci_df.iterrows():
        out.append({
            "run_id": str(row["run_id"]),
            "claimed_node_id": int(row["claimed_node_id"]),
            "window_start_seconds": float(row["window_start_seconds"]),
            "context": B.build_context(row),
        })
    if gated:
        print(f"[build_context_live] temporal class tokens WITHHELD from {gated}/"
              f"{len(ci_df)} cᵢ rows (GRU self-reported degenerate); the LLM sees no "
              f"temporal evidence rather than wrong evidence", flush=True)
    return out


def coverage_report(ci_df):
    """Per-source join coverage (fraction of anchor rows with that source present)."""
    n = len(ci_df)
    rep = {"anchor_rows": n,
           "identities": int(ci_df["claimed_node_id"].nunique()) if n else 0}
    for name, probe in (("rssi", "y_hat_i"), ("trust", "T_composite"),
                        ("ensemble", "y_hat_ens"), ("mobility", "v_rel")):
        if probe in ci_df.columns:
            cov = int(ci_df[probe].notna().sum())
            rep[name] = f"{cov}/{n} ({100 * cov / n:.1f}%)" if n else "0/0"
        else:
            rep[name] = "absent"
    return rep

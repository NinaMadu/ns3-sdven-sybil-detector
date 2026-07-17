"""
mobility_live — real-time twin of ml/fusion/mobility_tokens.py.

Computes the Eq 3.31 mobility tokens {v_rel, rho_c, dt_sync} for the current SCORE
window directly from the daemon's already-cached communication-log rows (no CSV read,
no manifest, no labels). Delegates the actual math to mobility_tokens.tokens_from_df so
the live tokens are byte-identical to the offline ones the LLM trained on.

Needs these communication-log columns present in the passed rows:
    receive_time, claimed_node_id, bsm_speed, observer_obu_id
(observer_obu_id must be added to the daemon comm_cache column filter — it is NOT in
temporal_xgb's USE_COLS). rho_c compares an identity's observer set to its PREVIOUS
window; on the bounded live slice that predecessor is present for every emitted (recent)
window as long as the slice spans >= 2 grid steps (window_margin default 30 s >> 2 s),
so rho_c matches offline except for identities whose prior window predates the slice —
the same bounded-window approximation temporal_xgb's gap_since_prev_window already accepts.
"""

import os
import sys

import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fusion"))
import mobility_tokens as MT  # noqa: E402  (tokens_from_df + snap_grid via identity_manifest)

# communication-log columns the mobility tokens consume
MOBILITY_COLS = ["receive_time", "claimed_node_id", "bsm_speed", "observer_obu_id"]

_EMPTY = pd.DataFrame(
    columns=["run_id", "claimed_node_id", "window_start_seconds", "v_rel", "rho_c", "dt_sync"])


def build_mobility_live(rows, run_id):
    """rows: a communication-log slice DataFrame (e.g. comm_recent). Returns the mobility
    tokens keyed by (run_id, claimed_node_id, window_start_seconds) for assemble_ci's
    `mobility=` source, or an empty frame if there is nothing to compute."""
    if rows is None or len(rows) == 0:
        return _EMPTY.copy()
    have = [c for c in MOBILITY_COLS if c in rows.columns]
    if "receive_time" not in have or "claimed_node_id" not in have:
        return _EMPTY.copy()
    df = rows[have].copy()
    if "observer_obu_id" not in df.columns:
        # comm_cache filter not extended — rho_c would be undefined; emit NaN so cᵢ still
        # carries v_rel/dt_sync rather than dropping the whole mobility source.
        df["observer_obu_id"] = pd.NA
    out = MT.tokens_from_df(df, run_id, verbose=False)
    return out if out is not None and len(out) else _EMPTY.copy()

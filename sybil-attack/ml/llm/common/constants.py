"""
Canonical constants for the single-head LLM detector — the ONE place the 7-class
taxonomy, the run-scoped join key, and the shared paths are defined.

Kept byte-for-byte aligned to the vehicle-tier detectors (v2/v3):
  - CLASS_NAMES mirrors ml/trust_v2/trust_v2_lib.py CLASS_NAMES (index == attack_type).
  - JOIN_KEY is the exact 5-column key every detector parquet exports
    (RSSI v2 / GRU v3 / trust v2 all use it), so cᵢ inner-joins cleanly.

Import this everywhere instead of re-declaring class lists (that drift was the
6-class / 5-class bug across candidates.py, eval_model.py, build_evidence.py).
"""

import os

# ── 7-class taxonomy — authoritative, index == attack_type == p_temp column k ──
CLASS_NAMES = {0: "legitimate", 1: "outsider", 2: "sim", 3: "nonsim",
               4: "indirect", 5: "malicious_rsu", 6: "malicious_controller"}
ATTACK_CLASSES = [CLASS_NAMES[i] for i in range(len(CLASS_NAMES))]   # ordered 0..6
NAME_TO_ID = {v: k for k, v in CLASS_NAMES.items()}
N_CLASSES = len(CLASS_NAMES)

# malicious_controller (6) is a control-plane attack: it does NOT appear as a
# vehicle beacon, so the 3 vehicle-tier detectors emit only 0..5. Class 6 is
# detectable only via RSU-tier signals (ŷ_ens / RSU trust). Keep it in the label
# space for fidelity; expect ~0 vehicle-tier windows for it.
VEHICLE_TIER_CLASSES = [CLASS_NAMES[i] for i in range(6)]            # 0..5

# ── run-scoped join key — the 5 cols every detector parquet carries ──
JOIN_KEY = ["run_id", "attack_percentage", "claimed_node_id",
            "window_start_seconds", "split"]
LABEL_COLS = ["is_sybil", "attack_type"]

# ── φ dimensions (Eq 3.18 concat = 32 + 32 + 16 = 80) ──
PHI_RSSI_DIM, PHI_TEMP_DIM, PHI_TRUST_DIM = 32, 32, 16
RSSI_PHI = [f"phi_rssi_{i}" for i in range(PHI_RSSI_DIM)]
TEMP_PHI = [f"phi_temp_{i}" for i in range(PHI_TEMP_DIM)]
TEMP_PROB = [f"p_temp_{k}" for k in range(N_CLASSES)]                 # 7-class softmax
TRUST_PHI = [f"phi_trust_{i}" for i in range(PHI_TRUST_DIM)]

# ── shared paths (reorganized tree; this file lives in ml/llm/common/) ──
_HERE = os.path.dirname(os.path.abspath(__file__))                   # ml/llm/common
ML_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))          # sybil-attack/ml

# fusion/spine = the promoted vehicle-tier exports the LLM consumes (ONE seam).
SPINE_DIR = os.path.join(ML_ROOT, "fusion", "spine")
# fusion/outputs = Eq 3.18/3.20 intermediates (fusion_head, ensemble, mobility).
FUSION_DIR = os.path.join(ML_ROOT, "fusion", "outputs")
ANALYZERS_DIR = os.path.join(ML_ROOT, "analyzers")
# back-compat: code that wrote/read "detector exports" now uses the fusion dir.
OUTPUTS_DIR = FUSION_DIR

SPLIT_MAP = os.path.join(SPINE_DIR, "split_map.parquet")
TEMPORAL_PARQUET = os.path.join(SPINE_DIR, "temporal_vehicle_tier.parquet")
RSSI_PARQUET = os.path.join(SPINE_DIR, "rssi_vehicle_tier.parquet")
TRUST_PARQUET = os.path.join(SPINE_DIR, "trust_vehicle_tier.parquet")

# RSU-tier XGB detector exports (Eq 3.20 ensemble inputs) now live per-analyzer.
RSU_TEMPORAL_XGB = os.path.join(ANALYZERS_DIR, "temporal_xgb_rsu", "outputs",
                                "temporal_xgb_rsu.parquet")
RSU_RSSI_XGB = os.path.join(ANALYZERS_DIR, "rssi_xgb_rsu", "outputs",
                            "rssi_xgb_rsu.parquet")

# Canonical cᵢ table (Eq 3.31) — written by common/build_context_vector.py and
# consumed by BOTH stages. Anchored to this file's dir (llm/common), so every
# consumer resolves the same path regardless of its own location. (Previously
# stage2_agents/build_agent_datasets.py derived it from its own dir and looked
# in the wrong place after the 2026-07-13 reorg.)
CONTEXT_DIR = os.path.join(_HERE, "context")
C_I_PARQUET = os.path.join(CONTEXT_DIR, "c_i.parquet")


def class_name(i):
    """attack_type int -> class string."""
    return CLASS_NAMES.get(int(i), "legitimate")


def class_id(name):
    """class string -> attack_type int (defaults to legitimate)."""
    return NAME_TO_ID.get(name, 0)

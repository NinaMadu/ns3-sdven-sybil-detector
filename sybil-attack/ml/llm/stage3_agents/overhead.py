"""
Stage-3 STEP 7 — LLM-FL communication overhead (Eq 3.71 / 3.72).

Two numbers per the supervisor's instruction — report BOTH, never silently
change Eq 3.71:

  1. ANALYTICAL payload (Eq 3.71, exact):
         Omega_LLM-FL = 3 · b_prec · Σ_m r(d_m + k_m)
     where the factor 3 = three agents, and the sum is over every LoRA target
     matrix m. The full-weight comparison and the saving:
         Omega_full   = 3 · b_prec · Σ_m d_m·k_m
         zeta_LoRA    = (1 − Omega_LLM-FL / Omega_full) · 100%

  2. MEASURED network bytes for the real four-RSU round:
         upload   = Σ_zones bytes(local a1,a2,a3 adapters)
         download = Σ_zones bytes(global a1,a2,a3 adapters)   (redistributed to all)
         total    = upload + download

Both Σr(d+k) and Σd·k are derived straight from one saved adapter's tensors:
each module has lora_A [r, k] and lora_B [d, r], so d·k = B.shape[0]·A.shape[1].
No base-model load required.
"""

import argparse
import json
import os
import re

from safetensors.torch import load_file


def analytical(adapter_dir, n_agents=3, b_prec=2):
    """Eq 3.71/3.72 from one representative agent adapter (all agents share shape)."""
    sd = load_file(os.path.join(adapter_dir, "adapter_model.safetensors"))
    # pair lora_A / lora_B per module stem
    a_shapes, b_shapes = {}, {}
    for k, v in sd.items():
        stem = re.sub(r"\.lora_[AB]\.weight$", "", k)
        if ".lora_A." in k:
            a_shapes[stem] = tuple(v.shape)     # [r, k_in]
        elif ".lora_B." in k:
            b_shapes[stem] = tuple(v.shape)     # [d_out, r]
    sum_r_dk = 0     # Σ_m r(d+k)      = LoRA transmitted params (one agent)
    sum_dk = 0       # Σ_m d·k         = full-weight params      (one agent)
    for stem in a_shapes:
        r, k = a_shapes[stem]
        d, r2 = b_shapes[stem]
        assert r == r2, f"rank mismatch at {stem}"
        sum_r_dk += r * (d + k)
        sum_dk += d * k
    omega_lora = n_agents * b_prec * sum_r_dk
    omega_full = n_agents * b_prec * sum_dk
    return {
        "n_agents": n_agents, "b_prec_bytes": b_prec,
        "per_agent_lora_params_sum_r_dk": int(sum_r_dk),
        "per_agent_full_params_sum_dk": int(sum_dk),
        "omega_llm_fl_bytes": int(omega_lora),
        "omega_llm_fl_MB": round(omega_lora / 1e6, 3),
        "omega_full_weight_bytes": int(omega_full),
        "omega_full_weight_MB": round(omega_full / 1e6, 3),
        "zeta_lora_saving_pct": round((1 - omega_lora / omega_full) * 100, 4),
    }


def _adapter_bytes(d):
    f = os.path.join(d, "adapter_model.safetensors")
    return os.path.getsize(f) if os.path.exists(f) else 0


def measured(local_dirs, global_dirs, n_zones):
    """local_dirs/global_dirs: lists of adapter dirs actually serialized this round."""
    upload = sum(_adapter_bytes(d) for d in local_dirs)
    download = n_zones * sum(_adapter_bytes(d) for d in global_dirs)   # sent to every zone
    return {
        "measured_upload_bytes": int(upload),
        "measured_download_bytes": int(download),
        "measured_total_bytes": int(upload + download),
        "measured_total_MB": round((upload + download) / 1e6, 3),
        "counting_convention": "adapter safetensors payload only (bf16 LoRA A/B); "
                               "excludes optimizer state, transport headers, "
                               "secure-aggregation and compression.",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, help="one representative agent adapter dir")
    args = ap.parse_args()
    print(json.dumps(analytical(args.adapter), indent=2))


if __name__ == "__main__":
    main()

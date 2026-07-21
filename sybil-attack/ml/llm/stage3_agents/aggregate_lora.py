"""
Stage-3 STEP 4 — Equation 3.32 at the SDN controller.

Dataset-size-weighted direct averaging of the local LoRA matrices, per agent:

        (B̄, Ā) = Σ_r |D_r|·(B_r, A_r) / Σ_r |D_r|
        p_r = |D_r| / Σ_j |D_j|
        A_global = Σ_r p_r·A_r ,   B_global = Σ_r p_r·B_r

Every zone adapter MUST share the same base checkpoint, target modules, rank,
alpha and tensor keys — this loader verifies keys/shapes match before averaging
and refuses otherwise. Output is the bf16 global adapter + an aggregation manifest
(zone ids, |D_r|, weights p_r, input/output tensor hashes, sizes) for auditing.

Usable standalone; normally called by run_federation.py.
    ml/.venv/bin/python aggregate_lora.py \
        --zone runs/<exp>/round_001/local/H0/zone_1/a1:5138 \
        --zone runs/<exp>/round_001/local/H0/zone_2/a1:5138 ... \
        --template runs/<exp>/round_001/local/H0/zone_1/a1 \
        --out runs/<exp>/round_001/global/a1
"""

import argparse
import hashlib
import json
import os
import shutil

import torch
from safetensors.torch import load_file, save_file


def _hash(sd):
    h = hashlib.sha256()
    for k in sorted(sd):
        h.update(k.encode())
        h.update(sd[k].float().cpu().numpy().tobytes())
    return h.hexdigest()[:16]


def aggregate(zone_paths, weights, template, out):
    """zone_paths: list of adapter dirs; weights: matching |D_r| list."""
    p = [w / sum(weights) for w in weights]                # normalized p_r
    states = [load_file(os.path.join(d, "adapter_model.safetensors")) for d in zone_paths]

    keys = set(states[0])
    for i, s in enumerate(states[1:], 1):
        if set(s) != keys:
            raise ValueError(f"tensor-key mismatch zone0 vs zone{i}: "
                             f"{keys ^ set(s)}")
        for k in keys:
            if s[k].shape != states[0][k].shape:
                raise ValueError(f"shape mismatch {k}: {states[0][k].shape} vs {s[k].shape}")

    glob = {}
    for k in keys:
        acc = torch.zeros_like(states[0][k], dtype=torch.float32)
        for pr, s in zip(p, states):
            acc += pr * s[k].float()
        glob[k] = acc.to(torch.bfloat16).contiguous()

    os.makedirs(out, exist_ok=True)
    # carry the (identical) adapter_config.json from the template zone adapter
    shutil.copy(os.path.join(template, "adapter_config.json"),
                os.path.join(out, "adapter_config.json"))
    save_file(glob, os.path.join(out, "adapter_model.safetensors"), metadata={"format": "pt"})

    manifest = {
        "equation": "3.32 (dataset-size-weighted LoRA A/B averaging)",
        "zones": [{"path": d, "n_D_r": int(w), "p_r": round(pr, 6),
                   "in_hash": _hash(s)}
                  for d, w, pr, s in zip(zone_paths, weights, p, states)],
        "sum_D": int(sum(weights)),
        "n_tensors": len(keys),
        "adapter_params": int(sum(v.numel() for v in glob.values())),
        "out_size_mb": round(os.path.getsize(
            os.path.join(out, "adapter_model.safetensors")) / 1e6, 3),
        "out_hash": _hash(glob),
    }
    json.dump(manifest, open(os.path.join(out, "aggregation_manifest.json"), "w"), indent=2)
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zone", action="append", required=True,
                    help="repeatable: <adapter_dir>:<|D_r|>")
    ap.add_argument("--template", required=True, help="dir to copy adapter_config.json from")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    paths, weights = [], []
    for z in args.zone:
        d, w = z.rsplit(":", 1)
        paths.append(d)
        weights.append(float(w))
    man = aggregate(paths, weights, args.template, args.out)
    print(json.dumps(man, indent=2))


if __name__ == "__main__":
    main()

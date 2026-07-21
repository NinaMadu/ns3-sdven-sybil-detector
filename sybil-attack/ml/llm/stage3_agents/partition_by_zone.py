"""
Stage-3 STEP 1 — partition the Stage-2 training data into four RSU edge zones.

This is the ONE piece Stage-3 adds to the Stage-2 data path. It reads the same
canonical context table (llm/common/context/c_i.parquet), keeps the frozen
train/val/test split untouched, and splits ONLY the train rows into four disjoint
zones so each zone hits a target attacker fraction (the D1 heterogeneity endpoint).
val and test stay whole and shared, exactly as in Stage-2.

Attacker  = is_sybil == 1  (attack_type 1..6)
Legitimate= attack_type 0

For each endpoint (e.g. H0 = [.5,.5,.5,.5], Hmax = [.1,.3,.5,.7]) and each zone r
it draws a stratified, disjoint sample: rare attack types (e.g. malicious_rsu,
only ~120 train rows) are spread across zones in proportion to each zone's
attacker quota, so no zone silently loses a whole class for a reason unrelated to
the attacker-fraction manipulation under study.

Outputs (per endpoint):
    data_fl/<endpoint>/<agent>/zone_<r>/train.jsonl     balanced local train
    data_fl/<endpoint>/zone_manifest.json               |D_r| + per-class counts
Shared, endpoint-independent, written once:
    data_fl/shared/<agent>/{val,test}.jsonl             frozen eval sets

|D_r| recorded in the manifest is the RAW (pre-balance) zone size — that is the
real local dataset size and the Eq 3.32 aggregation weight. Balancing is applied
only to what the local trainer consumes (same balance_train as Stage-2), never to
|D_r|.

Run:  ml/.venv/bin/python partition_by_zone.py [--config fl_config.json]
"""

import argparse
import json
import os

import numpy as np
import pandas as pd

import fl_common as F
from fl_common import C, B, A


def feasible_equal_zone_size(fractions, n_attack, n_legit):
    """Largest EQUAL zone size N s.t. every zone's attacker/legit quota is
    drawable from the disjoint pools:  N*Σf ≤ n_attack  and  N*Σ(1-f) ≤ n_legit."""
    sf = sum(fractions)
    sl = sum(1.0 - f for f in fractions)
    cap_a = n_attack / sf if sf > 0 else float("inf")
    cap_l = n_legit / sl if sl > 0 else float("inf")
    return int(min(cap_a, cap_l))


def stratified_allocation(pool_by_type, quotas, rng):
    """Give each zone EXACTLY its attacker quota, with an attack-type mix that
    mirrors the global attacker type distribution, drawn disjointly across zones.

    pool_by_type: {attack_type_int -> shuffled list of row indices}
    quotas:       list of per-zone attacker counts (len n_zones)
    Returns:      list (len n_zones) of lists of row indices (disjoint).

    Total attackers consumed = Σ quotas (≤ pool); surplus attackers are left
    unused. If proportional rounding leaves a zone short (a rare type ran dry),
    it is backfilled from whatever attacker rows remain so |zone| == quota exactly.
    """
    n_zones = len(quotas)
    zones = [[] for _ in range(n_zones)]
    types = list(pool_by_type)
    total_att = sum(len(pool_by_type[t]) for t in types)
    if total_att == 0:
        return zones
    cursors = {t: 0 for t in types}                       # disjoint draw per type

    for z, q in enumerate(quotas):
        want = {t: q * len(pool_by_type[t]) / total_att for t in types}
        take = {t: int(np.floor(want[t])) for t in types}
        rem = q - sum(take.values())
        order = sorted(types, key=lambda t: want[t] - take[t], reverse=True)
        for t in order[:rem]:
            take[t] += 1
        for t in types:
            avail = pool_by_type[t][cursors[t]:cursors[t] + take[t]]
            cursors[t] += len(avail)
            zones[z].extend(avail)

    # backfill any zone that fell short (rare-type exhaustion) from leftovers
    leftover = []
    for t in types:
        leftover.extend(pool_by_type[t][cursors[t]:])
    rng.shuffle(leftover)
    lc = 0
    for z, q in enumerate(quotas):
        short = q - len(zones[z])
        if short > 0:
            zones[z].extend(leftover[lc:lc + short])
            lc += short
    for z in zones:
        rng.shuffle(z)
    return zones


def partition_endpoint(train, fractions, zone_size, seed):
    """Return (zone_frames, meta) for one endpoint. Disjoint zone subsets of the
    raw (unbalanced) train rows, each with |zone|==zone_size and the requested
    attacker fraction (rounded to integer counts)."""
    rng = np.random.default_rng(seed)
    n_zones = len(fractions)

    is_att = train["is_sybil"].astype(int) == 1
    att = train[is_att]
    leg = train[~is_att]

    # attacker quota per zone (integer), legit quota fills the rest
    att_q = [int(round(f * zone_size)) for f in fractions]
    leg_q = [zone_size - a for a in att_q]

    # ---- attackers: stratified by attack_type so rare types are spread ----
    pool_by_type = {}
    for t, sub in att.groupby("attack_type"):
        idx = sub.index.to_numpy()
        rng.shuffle(idx)
        pool_by_type[int(t)] = list(idx)
    att_zone_idx = stratified_allocation(pool_by_type, att_q, rng)

    # ---- legitimate: one pool, sequential disjoint draw ----
    leg_idx = leg.index.to_numpy()
    rng.shuffle(leg_idx)
    leg_idx = list(leg_idx)
    cur = 0
    leg_zone_idx = []
    for q in leg_q:
        leg_zone_idx.append(leg_idx[cur:cur + q])
        cur += q

    zone_frames, meta = [], []
    for z in range(n_zones):
        idx = list(att_zone_idx[z]) + list(leg_zone_idx[z])
        zf = train.loc[idx].sample(frac=1, random_state=seed + z).reset_index(drop=True)
        zone_frames.append(zf)
        by_class = {C.class_name(k): int((zf["attack_type"] == k).sum())
                    for k in range(C.N_CLASSES)}
        meta.append({
            "zone": z + 1,
            "target_attacker_fraction": fractions[z],
            "n_rows": int(len(zf)),                    # |D_r| for Eq 3.32
            "n_attackers": int((zf["is_sybil"] == 1).sum()),
            "actual_attacker_fraction": round(float((zf["is_sybil"] == 1).mean()), 4),
            "per_class": by_class,
        })
    return zone_frames, meta


def emit_zone_training(zf, endpoint, zone_id, balance=True):
    """Balance a zone's rows (same balance_train as Stage-2) and write the three
    per-agent train.jsonl files for that zone."""
    zf = zf.copy()
    zf["_label"] = zf["attack_type"].map(C.class_name)
    local = B.balance_train(zf) if balance else zf
    ctx = [(B.build_context(r), r["_label"]) for _, r in local.iterrows()]
    n_bal = 0
    for agent in A.AGENT_ORDER:
        recs = [F.chat_record(agent, ci, label) for ci, label in ctx]
        out = os.path.join(F.DATA_DIR, endpoint, agent, f"zone_{zone_id}", "train.jsonl")
        n_bal = F.write_jsonl(out, recs)
    return n_bal


def emit_shared_eval(df):
    """Write the frozen, endpoint-independent val/test jsonl per agent (once)."""
    counts = {}
    for split in ("val", "test"):
        sub = df[df["split"] == split].copy()
        sub["_label"] = sub["attack_type"].map(C.class_name)
        ctx = [(B.build_context(r), r["_label"]) for _, r in sub.iterrows()]
        for agent in A.AGENT_ORDER:
            recs = [F.chat_record(agent, ci, label) for ci, label in ctx]
            out = os.path.join(F.DATA_DIR, "shared", agent, f"{split}.jsonl")
            counts[split] = F.write_jsonl(out, recs)
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(F._HERE, "fl_config.json"))
    ap.add_argument("--context", default=C.C_I_PARQUET)
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    pcfg = cfg["partition"]
    seed = pcfg["seed"]
    endpoints = pcfg["endpoints"]

    df = pd.read_parquet(args.context)
    train = df[df["split"] == "train"].copy()
    n_attack = int((train["is_sybil"] == 1).sum())
    n_legit = int((train["is_sybil"] == 0).sum())
    print(f"train rows={len(train)}  attackers={n_attack}  legit={n_legit}  "
          f"(overall attacker frac={n_attack/len(train):.3f})")

    # zone_size: 'auto' = min feasible EQUAL size across ALL endpoints, so every
    # zone in every endpoint has the same |D_r| (cleanest control).
    if pcfg["zone_size"] == "auto":
        zone_size = min(feasible_equal_zone_size(e["attacker_fractions"], n_attack, n_legit)
                        for e in endpoints.values())
    else:
        zone_size = int(pcfg["zone_size"])
    print(f"equal zone_size = {zone_size}  ->  {zone_size*len(next(iter(endpoints.values()))['attacker_fractions'])} train rows used per endpoint\n")

    # shared frozen eval sets (identical to Stage-2 val/test), written once
    ec = emit_shared_eval(df)
    print(f"[shared] frozen val/test per agent: {ec}\n")

    summary = {"zone_size": zone_size, "seed": seed,
               "train_pool": {"attackers": n_attack, "legit": n_legit},
               "endpoints": {}}
    for name, e in endpoints.items():
        fr = e["attacker_fractions"]
        zone_frames, meta = partition_endpoint(train, fr, zone_size, seed)
        for z, zf in enumerate(zone_frames, start=1):
            n_bal = emit_zone_training(zf, name, z)
            meta[z - 1]["n_rows_balanced_for_train"] = n_bal
        man = {"endpoint": name, "label": e["label"],
               "attacker_fractions": fr, "zone_size": zone_size, "zones": meta}
        mp = os.path.join(F.DATA_DIR, name, "zone_manifest.json")
        os.makedirs(os.path.dirname(mp), exist_ok=True)
        json.dump(man, open(mp, "w"), indent=2)
        summary["endpoints"][name] = meta

        print(f"=== endpoint {name} ({e['label']})  target={fr} ===")
        hdr = f"{'zone':>4} {'|D_r|':>7} {'att%':>6} " + " ".join(
            f"{C.class_name(k)[:8]:>8}" for k in range(C.N_CLASSES))
        print(hdr)
        for m in meta:
            row = f"{m['zone']:>4} {m['n_rows']:>7} {m['actual_attacker_fraction']*100:>5.1f}% "
            row += " ".join(f"{m['per_class'][C.class_name(k)]:>8}" for k in range(C.N_CLASSES))
            print(row)
        print()

    sp = os.path.join(F.DATA_DIR, "partition_summary.json")
    json.dump(summary, open(sp, "w"), indent=2)
    print(f"wrote {sp}")


if __name__ == "__main__":
    main()

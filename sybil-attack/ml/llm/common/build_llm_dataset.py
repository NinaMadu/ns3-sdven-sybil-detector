"""
Build the single-head LLM fine-tuning dataset from the aligned context table.

Consumes llm/common/context/c_i.parquet (constants.C_I_PARQUET) and emits one
{system, user=cᵢ, assistant=verdict, split} record per window, 7-class.

The user message is the Eq 3.31 context vector grouped into its four token sets
(feature ‖ signatures S1..S6 ‖ trust T(i,t)+subfields ‖ mobility) plus the
ensemble score ŷ_ens. The LLM reads interpretable detector SCORES/observations —
not the raw 32-d φ latents (those feed the numeric Eq 3.18 head upstream of
ŷ_ens, not the text prompt). Every group is optional: an absent detector is
simply omitted and the model is trained to reason over what is present.

FP-preserving balance: minority ATTACK classes are oversampled; the legitimate
class is NEVER down-sampled (fixes build_llm_dataset_v3 bug #8). val/test are
left untouched.

Runs in ml/.venv (pandas/numpy). Output: ml/fullmode/data/llm_dataset.jsonl
"""

import argparse
import json
import os

import numpy as np
import pandas as pd

import constants as C

_HERE = os.path.dirname(os.path.abspath(__file__))
DEF_IN = C.C_I_PARQUET          # canonical cᵢ path (constants hub)
DEF_OUT = os.path.join(_HERE, "data", "llm_dataset.jsonl")

SYSTEM_PROMPT = (
    "You are a Sybil-attack detector for a vehicular network. You receive a "
    "context vector for one claimed vehicle identity over a short time window: "
    "detector scores, per-attack signature scores, a cumulative trust token with "
    "signal/behaviour/history sub-scores, and mobility measures (relative "
    "velocity, topology churn, handoff-sync gap). Mobility matters: a fast "
    "vehicle with shifting signal can be perfectly legitimate. Weigh the evidence, "
    "decide whether the identity is legitimate or which of the six Sybil attack "
    "types it is, and justify it by citing the context. Respond in JSON."
)


def _num(v, nd=4):
    try:
        f = float(v)
        return None if np.isnan(f) else round(f, nd)
    except (TypeError, ValueError):
        return None


def _present(row, cols):
    return [c for c in cols if c in row.index and _num(row[c]) is not None]


def build_context(row, drop_identifiers=False):
    """cᵢ as the Eq 3.31 token groups — only populated from columns that exist.

    drop_identifiers: omit claimed_id / window_start_s / run. These are NOT
    detection evidence — in the seq6 dataset the attack type is a fixed function
    of the time phase, so `window_start_s`+`run` leak the label, and Sybil
    claimed_ids are numbered >= N_Vehicles so `claimed_id` leaks sybil-vs-legit.
    Dropping them forces the model to judge from signatures only (Stage-0 honest
    eval)."""
    if drop_identifiers:
        ci = {}
    else:
        ci = {"claimed_id": int(row["claimed_node_id"]),
              "window_start_s": _num(row["window_start_seconds"], 2),
              "run": str(row["run_id"])}

    # ── feature tokens: f_rssi, f_temp (+ f_beacon, f_token when present) ──
    feat = {}
    ptemp = _present(row, C.TEMP_PROB)
    if ptemp:                                        # 7-class temporal softmax
        probs = {C.class_name(k): _num(row[f"p_temp_{k}"]) for k in range(C.N_CLASSES)
                 if f"p_temp_{k}" in row.index and _num(row[f"p_temp_{k}"]) is not None}
        p_sybil = _num(1.0 - row["p_temp_0"]) if _num(row.get("p_temp_0")) is not None else None
        pred = max(probs, key=probs.get) if probs else None
        feat["temporal"] = {"p_sybil": p_sybil, "pred": pred, "class_probs": probs}
    if _num(row.get("y_hat_i")) is not None:         # RSSI vehicle-tier P(sybil)
        feat["rssi"] = {"p_sybil": _num(row["y_hat_i"])}
    for k, col in (("beacon_rate_dev", "raw_rate_deviation"),
                   ("iat_entropy", "iat_entropy"), ("token_valid", "token_valid")):
        if _num(row.get(col)) is not None:
            feat.setdefault("beacon", {})[k] = _num(row[col])
    if feat:
        ci["features"] = feat

    # ── signature tokens S1..S6 ──
    sig = {f"S{i}": _num(row[f"s{i}"]) for i in range(1, 7)
           if f"s{i}" in row.index and _num(row[f"s{i}"]) is not None}
    if sig:
        ci["signatures"] = sig

    # ── trust token T(i,t) + interpretable sub-fields + FP evidence ──
    trust = {}
    if _num(row.get("T_composite")) is not None:
        trust["T_composite"] = _num(row["T_composite"])
    if _num(row.get("phi_trust_score")) is not None:
        trust["p_sybil"] = _num(row["phi_trust_score"])
    for k, col in (("T_RSSI", "T_RSSI"), ("T_behav", "T_behav"), ("T_hist", "T_hist")):
        if _num(row.get(col)) is not None:
            trust[k] = _num(row[col])
    ev = {}
    for k, col in (("rssi_mismatch_frac", "rssi_mismatch_frac"),
                   ("identity_lifetime_s", "identity_lifetime"),
                   ("rsu_report_count", "rsu_report_count"),
                   ("rsu_verified_prob", "rsu_verified_prob"),
                   ("controller_trust", "ctrl_trust")):
        if _num(row.get(col)) is not None:
            ev[k] = _num(row[col])
    if ev:
        trust["evidence"] = ev
    if trust:
        ci["trust"] = trust

    # ── mobility tokens: v_rel, rho_c (topology churn), dt_sync (handoff) ──
    mob = {}
    for k, col in (("v_rel", "v_rel"), ("topology_churn", "rho_c"),
                   ("handoff_sync_gap_s", "dt_sync")):
        if _num(row.get(col)) is not None:
            mob[k] = _num(row[col])
    if mob:
        ci["mobility"] = mob

    # ── ensemble score ŷ_ens (Eq 3.20) ──
    if _num(row.get("y_hat_ens")) is not None:
        ci["y_hat_ensemble"] = _num(row["y_hat_ens"])
    return ci


def build_reasoning(label, ci):
    parts = []
    feat = ci.get("features", {})
    t = feat.get("temporal", {})
    if t.get("p_sybil") is not None:
        tag = "high" if t["p_sybil"] > 0.6 else "low" if t["p_sybil"] < 0.4 else "mid"
        parts.append(f"Temporal detector: p_sybil={t['p_sybil']:.3f} ({tag}), "
                     f"pred='{t.get('pred')}'.")
    if "rssi" in feat:
        parts.append(f"RSSI detector: p_sybil={feat['rssi']['p_sybil']:.3f}.")
    tr = ci.get("trust", {})
    if tr:
        cues = []
        e = tr.get("evidence", {})
        if e.get("rssi_mismatch_frac", 0) > 0.3:
            cues.append(f"RSSI mismatch {e['rssi_mismatch_frac']:.2f}")
        if e.get("identity_lifetime_s") is not None and e["identity_lifetime_s"] < 5:
            cues.append(f"short identity lifetime {e['identity_lifetime_s']:.1f}s")
        if e.get("rsu_report_count") is not None and e["rsu_report_count"] < 5:
            cues.append(f"low RSU corroboration ({e['rsu_report_count']:.0f})")
        tail = f" — {', '.join(cues)}" if cues else ""
        tc = tr.get("T_composite")
        parts.append(f"Trust: T_composite={tc:.3f}{tail}." if tc is not None
                     else f"Trust evidence{tail}.")
    mob = ci.get("mobility", {})
    if mob:
        parts.append(f"Mobility: v_rel={mob.get('v_rel')}, "
                     f"churn={mob.get('topology_churn')} — "
                     f"{'consistent with honest high-mobility travel' if label == 'legitimate' else 'inconsistent with claimed motion'}.")
    concl = {
        "legitimate": "Evidence is consistent with a genuine vehicle. Verdict: legitimate.",
        "outsider": "Foreign identity without mobility corroboration. Verdict: outsider Sybil.",
        "sim": "Concurrent pseudonyms from one node. Verdict: simultaneous (sim) Sybil.",
        "nonsim": "Sequential pseudonym cycling. Verdict: non-simultaneous (nonsim) Sybil.",
        "indirect": "Anomaly relayed through a compromised node. Verdict: indirect Sybil.",
        "malicious_rsu": "RSU-tier fabrication of vehicle records. Verdict: malicious RSU.",
        "malicious_controller": "Control-plane fabrication. Verdict: malicious controller.",
    }
    parts.append(concl.get(label, f"Verdict: '{label}'."))
    return " ".join(parts)


def build_target(label, ci):
    is_sybil = label != "legitimate"
    t = ci.get("features", {}).get("temporal", {})
    ps = t.get("p_sybil")
    conf = "high" if ps is not None and (ps > 0.8 or ps < 0.2) else "medium"
    return {"verdict": "sybil" if is_sybil else "legitimate",
            "attack_type": label, "confidence": conf,
            "reasoning": build_reasoning(label, ci)}


def balance_train(tr, seed=42):
    """Oversample minority ATTACK classes; keep ALL legitimate rows (never
    down-sample legit — protects the false-positive rate)."""
    rng = np.random.default_rng(seed)
    by = {c: sub for c, sub in tr.groupby("_label")}
    attack_sizes = [len(v) for c, v in by.items() if c != "legitimate" and len(v)]
    target = max(attack_sizes) if attack_sizes else 0
    out = []
    for c, sub in by.items():
        if c == "legitimate" or len(sub) >= target or len(sub) == 0:
            out.append(sub)                                   # keep as-is
        else:
            extra = sub.iloc[rng.choice(len(sub), size=target - len(sub), replace=True)]
            out.append(pd.concat([sub, extra]))
    return pd.concat(out).sample(frac=1, random_state=seed).reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", default=DEF_IN)
    ap.add_argument("--out", default=DEF_OUT)
    ap.add_argument("--balance", action="store_true", default=True)
    ap.add_argument("--no-balance", dest="balance", action="store_false")
    ap.add_argument("--drop-identifiers", action="store_true", default=False,
                    help="omit claimed_id/window_start_s/run (Stage-0 leak-free eval)")
    args = ap.parse_args()

    df = pd.read_parquet(args.context)
    df["_label"] = df["attack_type"].map(C.class_name)

    tr = df[df["split"] == "train"].copy()
    if args.balance:
        tr = balance_train(tr)
    emit = pd.concat([tr, df[df["split"] == "val"], df[df["split"] == "test"]],
                     ignore_index=True)

    outdir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(outdir, exist_ok=True)
    # trainer/eval consume chat-format {"messages":[...]} splits directly, so the
    # buggy ml/finetune/prepare_data.py (wrong path, old file) is not needed.
    chat = {s: open(os.path.join(outdir, f"{s}.jsonl"), "w") for s in ("train", "val", "test")}
    counts, labels = {"train": 0, "val": 0, "test": 0}, {}
    with open(args.out, "w") as f:
        for _, row in emit.iterrows():
            label = row["_label"]
            ci = build_context(row, drop_identifiers=args.drop_identifiers)
            tgt = build_target(label, ci)
            user, asst = json.dumps(ci), json.dumps(tgt)
            f.write(json.dumps({"system": SYSTEM_PROMPT, "user": user,
                                "assistant": asst, "split": row["split"]}) + "\n")
            chat[row["split"]].write(json.dumps({"messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
                {"role": "assistant", "content": asst}]}) + "\n")
            counts[row["split"]] += 1
            labels[label] = labels.get(label, 0) + 1
    for fh in chat.values():
        fh.close()
    print(f"wrote {sum(counts.values()):,} examples -> {args.out}")
    print(f"  chat splits -> {outdir}/{{train,val,test}}.jsonl")
    print(f"  split : {counts}")
    print(f"  labels: {labels}")


if __name__ == "__main__":
    main()

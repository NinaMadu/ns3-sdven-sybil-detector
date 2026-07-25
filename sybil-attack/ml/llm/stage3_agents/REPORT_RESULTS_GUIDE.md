# Where the LLM-FL results go in the report (Chapter 5)

This maps the Stage-3 LLM-FL results to your report's Results sections: **which
subsection**, **what to write**, and **the exact file/command the numbers come from**.
All paths are under `ml/llm/stage3_agents/`.

The LLM-FL work touches **two** places in Chapter 5:
1. **§5.2 Internal Ablation Study** → the D1 comparison (LLM-FL vs Local-Only). PRIMARY.
2. **§5.3.7 Multi-Head LLM Decision Layer** → the federated training of the decision
   layer + its final metrics + the communication-overhead (ζ_LoRA) contribution.
3. **§5.3.8 Consolidated Cross-Tier Summary** → one row for the final LLM decision layer.

---

## 1. §5.2 Internal Ablation Study — Ablation D1  (PRIMARY home)

**What to add:** the D1 result — LLM-FL vs Local-Only across inter-zone heterogeneity —
plus the interaction discussion. This is the row `D1 | LLM-FL vs Local-Only` of Table 5.3.

**Table to insert (MCC-V is the D1 headline metric):**

| Zone attacker % | Condition | MCC-V | κ_conv | RC | Binary MCC | FPR |
|---|---|---:|---:|---:|---:|---:|
| 50/50/50/50 (homogeneous)   | Local-Only | 0.791  | not conv. by 5 | 0.918 | 0.993 | 0.0005 |
| 50/50/50/50                 | LLM-FL     | 0.779  | not conv. by 5 | 0.918 | 0.997 | 0.0004 |
| 10/30/50/70 (heterogeneous) | Local-Only | 0.767  | not conv. by 5 | 0.915 | 0.985 | 0.0003 |
| 10/30/50/70                 | **LLM-FL** | **0.802** | not conv. by 5 | 0.919 | 0.993 | 0.0004 |

**Text to write (the finding):**
- Under **homogeneous** zones, LLM-FL and Local-Only are effectively tied (0.779 vs
  0.791) — federation adds nothing when zones share the same distribution.
- Under **heterogeneous** zones, LLM-FL **outperforms** Local-Only (0.802 vs 0.767,
  +0.036 MCC-V; also at the binary level, 0.993 vs 0.985).
- **Mechanism** (cite the per-zone numbers): with Local-Only under heterogeneity the
  attack-poor zone 1 (10% attackers) is stranded at MCC-V **0.708**, while zone 4 (70%)
  reaches **0.835**; federation lifts every zone to one shared ~0.80 model.
  Per-zone Local (Hmax): `zone1 0.708, zone2 0.742, zone3 0.781, zone4 0.835`.
- **Convergence:** all four report "not converged by round 5" — validation MCC was still
  rising at the 5-round budget (Eq 3.73 rule: report this, do not substitute best round).

**Where to find:**
- Table → `runs/D1_results.md`
- Per-zone Local numbers → `runs/Hmax_local_seed42/history.json` (last `zone_mcc_macro`)
- Convergence curves (for a figure, MCC-V vs round):
  ```
  H0_local     : [0.0, 0.6946, 0.7231, 0.7344, 0.7663, 0.791]
  H0_llm_fl    : [0.0, 0.6879, 0.7318, 0.7333, 0.763,  0.7794]
  Hmax_local   : [0.0, 0.676,  0.7295, 0.7424, 0.7582, 0.7666]
  Hmax_llm_fl  : [0.0, 0.6164, 0.7215, 0.7434, 0.7799, 0.8025]
  ```
  (each in `runs/<exp>/history.json` → `mcc_macro_curve`; index = round 0..5)

> A convergence-curve figure (4 lines, MCC-V vs round) is the strongest visual here —
> Hmax/LLM-FL climbs past Hmax/Local by round 4–5.

---

## 2. §5.3.7 Multi-Head LLM Decision Layer

**What to add:** (a) that the decision layer is trained by four-zone LLM-FL (FedProx +
Eq 3.32 controller aggregation); (b) the final federated model's detection quality; and
(c) the LoRA communication-overhead contribution (ζ_LoRA).

**Final federated decision-layer metrics (Hmax LLM-FL, the deployed model):**

| Metric | Value |
|---|---:|
| Binary MCC | 0.993 |
| MCC-V (7-class) | 0.803 |
| FPR | 0.0004 |
| Macro-F1 | 0.527 |
| JSON-valid rate | 0.9998 |
| RC (reasoning consistency) | 0.919 |

**Per-variant recall (Hmax LLM-FL):**

| legitimate | outsider | sim | nonsim | indirect | malicious_rsu | malicious_controller |
|---:|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.90 | 0.51 | 0.83 | 0.59 | 0.43 | 0.00* |

\* control-plane variant, not observable in vehicle beacons (RSU-tier) — state this.

**Communication overhead (the ζ_LoRA / Ω_LLM-FL contribution):**

| Quantity | Value |
|---|---:|
| Adapter size per head (bf16 LoRA A/B only) | 18.5 MB (9,232,384 params) |
| Ω_LLM-FL per round (Eq 3.71, 3 agents) | 55.4 MB |
| Ω_full-weight (comparison) | 7,861 MB |
| **ζ_LoRA saving** | **99.30%** |
| Measured 4-RSU traffic per round | 444 MB |

**Where to find:**
- Metrics + per-class recall → `runs/Hmax_llm_fl_seed42/round_005/metrics.json`
- Overhead → `runs/Hmax_llm_fl_seed42/round_005/communication.json`
  or run: `../../.venv/bin/python overhead.py --adapter final_models/Hmax_llm_fl_seed42/a1`
- Adapter size proof → `ls -la final_models/Hmax_llm_fl_seed42/a1/adapter_model.safetensors`

> This subsection is also where the supervisor's Issue 2 fix is evidenced: the adapter
> is 18.5 MB (bf16 A/B only), matching the ~9.8 M-param / ~19.6 MB expectation, so ζ_LoRA
> is defensible.

---

## 3. §5.3.8 Consolidated Cross-Tier Summary

**What to add:** one row for the **LLM decision layer (LLM-FL)** in the cross-tier table,
alongside the trust / RSSI / temporal / XGBoost rows. Use the deployed (Hmax LLM-FL)
figures: Binary MCC 0.993, MCC-V 0.803, FPR 0.0004, RC 0.919.

**Where to find:** same `metrics.json` as §5.3.7.

---

## Quick source map

| Report location | Numbers | Source file / command |
|---|---|---|
| §5.2 D1 table | MCC-V, κ_conv, RC, binary, FPR (all 4 runs) | `runs/D1_results.md` |
| §5.2 per-zone | Local per-zone MCC-V | `runs/Hmax_local_seed42/history.json` |
| §5.2 curves/figure | MCC-V per round | `runs/<exp>/history.json` → `mcc_macro_curve` |
| §5.3.7 metrics | binary, MCC-V, FPR, F1, recall, JSON, RC | `runs/Hmax_llm_fl_seed42/round_005/metrics.json` |
| §5.3.7 overhead | Ω, ζ_LoRA, adapter size | `.../round_005/communication.json`, `overhead.py` |
| §5.3.8 summary | final LLM-layer row | same metrics.json |

Everything above is also collected in `EVIDENCE_PACK.md`.

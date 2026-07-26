# Triage of the supervisor's full-mode validation review

Which items belong to **our Stage-3 LLM-FL work**, which belong to **other models /
teammates**, and how to address each. Verified against the actual artifacts.

## Summary

| # | Item | Ours? | Effort | Status |
|---|---|---|---|---|
| 1 | Table says "no LLM-FL round executed" | ✅ ours | report edit | data ready |
| 2 | Adapter size 307/210 MB | ✅ ours | report edit | **already fixed + confirmed** |
| 3 | Dynamic trust weights ω_r + Ablation D3 | ✅ ours | **new work** | not implemented |
| 4 | Missing 60%/80% attacker runs → retrain all | ⚠️ shared | **large, upstream** | blocks/forces re-run |
| 5 | RSSI batch size 128 not in grid | ❌ not ours | — | RSSI analyser owner |
| 6 | Per-class MCC_k not computed directly | ⚠️ partly ours | small code + re-eval | affects all models |
| 7 | RSU Trust Approach 2 not executed | ❌ not ours | paper note | RSU trust owner |
| O1 | κ_conv not reported | ✅ ours | report edit | **data already exists** |
| O2 | D1 incomplete (only Hmax FL shown) | ✅ ours | report edit | **all 4 conditions exist** |
| O3 | Wrong equation ref for FedProx term | ✅ ours | report edit | LaTeX one-liner |

**Good news:** four of the items flagged against us (1, O1, O2, and half of 2) are
**already done** — the results exist, they just were not fully carried into the report.

---

## ✅ Items already solved — report edits only

### Issue 1 — Update the Precision row of `tab:llm-lora-config`
Replace "bf16 (central training; no LLM-FL round executed)" with the actual mode:

> bf16; **four-zone federated training (LLM-FL)** with FedProx local objective
> (μ = 0.01) and dataset-size-weighted adapter aggregation per `eq:llm_fl_agg`,
> run for 5 rounds at both heterogeneity endpoints (50/50/50/50 and 10/30/50/70).

### O1 — κ_conv^LLM-FL and the per-round MCC progression
We have both. Add to the report:

- **κ_conv = not converged by round 5** in all four conditions (validation MCC still
  rising at the round budget — this is the Eq 3.73 reporting rule, not a failure).
- **Per-round MCC-V curves** (round 0→5), from `runs/<exp>/history.json`:

| Condition | Round 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| H0 Local | 0.0 | 0.695 | 0.723 | 0.734 | 0.766 | 0.791 |
| H0 LLM-FL | 0.0 | 0.688 | 0.732 | 0.733 | 0.763 | 0.779 |
| Hmax Local | 0.0 | 0.676 | 0.730 | 0.742 | 0.758 | 0.767 |
| Hmax LLM-FL | 0.0 | 0.616 | 0.722 | 0.743 | 0.780 | **0.803** |

> If the supervisor wants an actual converged κ_conv value, we must extend
> `federation.max_rounds` (currently 5) and re-run — see "Decision needed" below.

### O2 — Ablation D1 is actually complete
All four conditions were executed; only the Hmax/FL one made it into the report. Add
the full table (`runs/D1_results.md`):

| Zone attacker % | Condition | MCC-V | RC | Binary MCC | FPR |
|---|---|---:|---:|---:|---:|
| 50/50/50/50 | Local-Only | 0.791 | 0.918 | 0.993 | 0.0005 |
| 50/50/50/50 | LLM-FL | 0.779 | 0.918 | 0.997 | 0.0004 |
| 10/30/50/70 | Local-Only | 0.767 | 0.915 | 0.985 | 0.0003 |
| 10/30/50/70 | LLM-FL | **0.802** | 0.919 | 0.993 | 0.0004 |

Plus the interaction finding (FL helps only under heterogeneity) and the per-zone
mechanism (Local strands zone 1 at 0.708 vs zone 4 at 0.835).

### O3 — Fix the FedProx equation reference
`~\ref{eq:convergence}` → the FedProx **local objective** equation (the
`μ/2·‖θ_r − θ_g‖²` proximal term), not the convergence bound. One-line LaTeX fix.

---

## ✅ Issue 2 — Adapter size: root cause found, fixed, confirmed

**Root cause (verified on disk):** the reported directory sizes included per-epoch
training checkpoints (each with a ~74 MB `optimizer.pt`), tokenizer/vocab files, and
the adapter tensors were stored in **fp32** rather than bf16.

Qwen `qwen1_5b_a1/` = 294 MB total: 2 × 122 MB `checkpoint-*/` + 14 MB tokenizer +
37 MB fp32 adapter. Same pattern for Llama.

**Confirmed adapter-only sizes (LoRA A/B matrices only, bf16):**

| Model | LoRA params | Adapter-only bf16 | Supervisor's estimate |
|---|---:|---:|---:|
| Qwen2.5-1.5B | 9,232,384 | **18.5 MB** | ~19.6 MB ✓ |
| Llama-3.2-1B | 5,636,096 | **11.3 MB** | ~12 MB ✓ |

Both match the expected values. Stage-3 already saves in this form —
`final_models/Hmax_llm_fl_seed42/a1/adapter_model.safetensors` = 18,516,456 bytes,
and a scan for `optimizer.pt` / `checkpoint-*` across all Stage-3 outputs returns
nothing.

**Corrected overhead metrics:** Ω_LLM-FL = 55.4 MB/round (3 agents),
Ω_full-weight = 7,861 MB, **ζ_LoRA = 99.30 %**.

**Action:** update the adapter-size row and the Ω/ζ_LoRA figures in the report to
these confirmed numbers. (The Llama 11.3 MB is computed from its actual tensor count;
if a re-saved bf16 Llama file is wanted as evidence, that is a 2-minute conversion.)

---

## 🔨 Issue 3 — Dynamic trust weights ω_r + Ablation D3  (NEW WORK, ours)

Currently ω is uniform (1/3, 1/3, 1/3) and frozen. The paper specifies dynamically
updated ω from the RSU endorser lifecycle (`eq:trust_demotion`), and Ablation D3
compares trust-weighted vs uniform consensus.

**What this needs:**
1. Implement the trust-demotion update rule so each agent/RSU weight degrades as its
   trust score drops.
2. Re-run consensus evaluation under both weightings (uniform vs dynamic) on the
   frozen test set — **inference only, no retraining**, so this is cheap (~1 eval pass
   each, not another 44-hour run).
3. Report D3 as a two-condition ablation.

**Note:** the consensus code already accepts an arbitrary ω vector
(`consensus_infer.consensus(D, PT, CF, omega, theta)`), so this is mostly the update
rule + an evaluation driver, not a redesign.

---

## ⚠️ Issue 6 — Per-class MCC_k  (partly ours)

We currently emit `per_class_recall`, not per-class MCC_k. This affects **every** model
in Chapter 5, not just ours.

**For our LLM layer:** add per-class MCC_k (one-vs-rest MCC per class) to
`evaluate_round.score()` and re-run the evaluation on the final promoted models. Cost:
one eval pass per model (~30–60 min), no retraining. We should also save the per-window
prediction parquet (Stage-3 currently does not) so future metrics can be derived without
re-running inference.

**For the other tiers:** their owners need to do the same in their notebooks.

---

## ❌ Not ours (route to the right owner)

- **Issue 5 — RSSI batch size 128 outside the {16,32,64} grid.** RSSI analyser owner.
  Easiest fix is to add 128 to the stated grid with the large-dataset justification.
- **Issue 7 — RSU Trust Approach 2 not executed.** RSU-trust owner; needs an explicit
  implementation-status note in the paper.

---

## ⚠️ Issue 4 — the one that affects everything (raise this first)

The supervisor wants all models retrained on the full attacker sweep
{20, 40, 60, 80, 100}%; we currently train on {20, 40, 100}%.

**Why this matters for us specifically:** our LLM-FL context table `c_i.parquet` is
built from those same simulation runs. If the 60% and 80% runs are added and the
detectors retrained, `c_i` changes → the four-zone partition changes → **the entire
44-hour Stage-3 D1 experiment must be re-run.**

**Therefore sequence matters:**
1. First decide whether Issue 4 is being done.
2. If yes → run the 60/80% sims, rebuild `c_i`, retrain the tier models, **then**
   re-run `run_d1.sh` (and only then finalise the LLM-FL numbers).
3. If no → the current LLM-FL numbers stand and only the report edits are needed.

Doing our fixes before that decision risks doing the 44-hour run twice.

---

## Suggested order of work

1. **Immediately (no compute):** report edits — Issue 1, O1, O2, O3, and the corrected
   adapter/ζ_LoRA numbers from Issue 2.
2. **Ask the supervisor** about Issue 4 sequencing (and whether an actual converged
   κ_conv is required, which needs more rounds).
3. **Then implement** Issue 3 (dynamic ω + D3) and our part of Issue 6 (per-class MCC_k)
   — both are inference-only and cheap.
4. **Forward** Issues 5 and 7 to their owners.

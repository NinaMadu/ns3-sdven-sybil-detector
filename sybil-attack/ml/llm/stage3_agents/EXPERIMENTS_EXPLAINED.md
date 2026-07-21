# What is actually running, and where the time goes

This explains the four experiments `run_d1.sh` runs, the exact processes inside
each one, the **real measured** time each step takes, and which steps can be cut
to speed things up (and what each cut costs you).

All numbers below are measured from the live H0/local run (Qwen2.5-1.5B, RTX 5090,
GPU at ~90% utilisation — i.e. compute-bound, not memory-bound).

---

## 1. The four experiments

`run_d1.sh` runs Ablation D1 = **2 conditions × 2 heterogeneity endpoints**, in this order:

| # | Experiment | Zones (attacker %) | Aggregation (Eq 3.32)? | Purpose |
|---|---|---|---|---|
| 1 | `H0_local`   | 50/50/50/50 | **No** | baseline, homogeneous |
| 2 | `H0_llm_fl`  | 50/50/50/50 | **Yes** | FL, homogeneous |
| 3 | `Hmax_local` | 10/30/50/70 | **No** | baseline, heterogeneous |
| 4 | `Hmax_llm_fl`| 10/30/50/70 | **Yes** | FL, heterogeneous |

The D1 result compares **local vs llm_fl** within each endpoint, then across endpoints.
Experiments 2 and 4 (`*_llm_fl`) produce the deployable federated models.

---

## 2. Anatomy of one experiment (`run_federation.py`)

Each experiment is a loop of **5 rounds** (`max_rounds` in `fl_config.json`) plus a
round 0 baseline:

```
round 0 : build shared init adapters (a1,a2,a3), evaluate them        (baseline)
round 1 : local training  ->  [aggregate if llm_fl]  ->  evaluate
round 2 : local training  ->  [aggregate if llm_fl]  ->  evaluate
...
round 5 : local training  ->  [aggregate if llm_fl]  ->  evaluate
=> write history.json (MCC curve + kappa_conv)
```

A "round" = one epoch of local training on each zone's own data, then evaluation.
See `README.md` for why local-only also uses rounds (fair D1 comparison).

---

## 3. Anatomy of ONE round — the actual processes

Every round launches a series of **subprocesses** (each loads the 1.5B base fresh).

### Training part (SAME in both conditions)
Twelve local LoRA fine-tunes = **3 agents × 4 zones**:

```
fedprox_train.py  agent=a1 zone=1     ┐
fedprox_train.py  agent=a2 zone=1     │
fedprox_train.py  agent=a3 zone=1     │  12 fine-tunes
...                                   │  (each ~11 min measured)
fedprox_train.py  agent=a3 zone=4     ┘
```
Measured: **~665 s (~11 min) per fine-tune** → **~2.2 h of training per round**.

### Aggregation part (llm_fl ONLY)
```
aggregate_lora.py  agent=a1  (average zone_1..4)   ┐  3 aggregations
aggregate_lora.py  agent=a2                        │  (seconds each —
aggregate_lora.py  agent=a3                        ┘  negligible)
```

### Evaluation part (DIFFERENT between conditions — this is the asymmetry)
Generation on the val set = the slow part of eval.

- **llm_fl:** evaluate ONE global 3-agent system → `3 agents × val_limit(4000)` = 12k generations → **~0.45 h/round**.
- **local:** evaluate FOUR per-zone systems (no shared model) → `4 zones × 3 agents × 4000` = 48k generations → **~1.8 h/round**.

---

## 4. Where the time ACTUALLY goes (measured)

| Round type | Training (12 fine-tunes) | Evaluation | **Total/round** |
|---|---:|---:|---:|
| `local` round | ~2.2 h | ~1.8 h | **~4.0 h** |
| `llm_fl` round | ~2.2 h | ~0.45 h | **~2.6 h** |

Full run (5 rounds each): `H0_local` ~20 h + `H0_llm_fl` ~13 h + `Hmax_local` ~20 h +
`Hmax_llm_fl` ~13 h ≈ **~2.5 days**.

**Key insight:** the **training** (twelve 11-minute fine-tunes = 2.2 h) is the
dominant, mostly-irreducible cost and is identical in both conditions. Evaluation
is the *second* cost and is 4× heavier for `local`. Sequence length is ~700 tokens
(p50 683, max 709) so `max_len` is NOT wasteful — that is not a lever.

---

## 5. Speedup levers — ranked, with the trade-off of each

### A. Reduce per-round eval — `eval.val_limit` 4000 → 1000  ✅ safe, recommended
- **Saves:** local eval 1.8 h → ~0.45 h/round (**~1.35 h/round**); llm_fl ~0.45 → ~0.11 h.
- **Cost:** per-round convergence curve uses 1000 val windows instead of 4000 — still
  a stable MCC estimate for Eq 3.73. Compute the **final** headline MCC-V once on the
  full val+test at the end (separate step), so the reported number stays full-resolution.
- **Paper impact:** none — training is untouched; only how many windows the *monitoring*
  eval uses changes.
- **Total effect:** ~2.5 days → **~1.7 days**.

### B. Skip the round-0 baseline eval  ✅ safe, tiny
- **Saves:** one eval per experiment (the untrained init always scores ~0).
- **Cost:** you lose the "round 0" point on the curve (it is just the random baseline).
- **Total effect:** small (~1–2 h across the whole run).

### C. Reduce `eval.max_new_tokens` 128 → 96  ✅ safe, small
- **Saves:** generation stops sooner; the agents emit short JSON, so this trims eval a bit.
- **Cost:** none as long as 96 tokens still fits the JSON verdict (it does).

### D. Keep the base model resident across the 12 fine-tunes  ⚠ code change, moderate
- **Saves:** ~12 model reloads/round × ~40 s ≈ **~8 min/round** (~2.7 h total).
- **Cost:** a non-trivial refactor of `run_federation`/`fedprox_train` (currently each
  fine-tune is an isolated subprocess for clean GPU memory); some OOM risk.

### E. Faster training (batch 8→16 / disable grad-checkpoint)  ⚠ risky, low payoff here
- **Why low payoff:** the GPU is already ~90% utilised (compute-bound), so a bigger
  batch mostly reduces per-step overhead, not the core FLOPs. Disabling gradient
  checkpointing could OOM (only ~8 GB headroom) and would change memory behaviour.
- **Recommendation:** leave the training recipe as-is to stay paper-faithful and stable.

### F. Fewer rounds (5 → 3)  ❌ not advised
- **Cost:** Eq 3.73 `kappa_conv` needs **5 consecutive** evaluated rounds; with 3 you
  cannot compute the convergence metric at all. 5 is the minimum. Keep it.

### G. Run only what you need  ✅ scope choice
- The two `*_llm_fl` experiments give the deployable FL models. If you only need a
  first complete D1 comparison, run **one endpoint** first: `bash run_d1.sh H0`.

---

## Recommended combination (safe, no paper deviation)

**A + B + C**: `val_limit 1000`, skip round-0 eval, `max_new_tokens 96`. Training is
untouched, so the FL method and its results are exactly as designed — only the
monitoring evaluation is made lighter. Expected: **~2.5 days → ~1.6–1.7 days**, and
because `run_d1.sh` uses `--resume`, the fine-tunes already completed (H0/local
rounds 1–4) are reused, not repeated.

> The hard floor is the training: 12 fine-tunes × ~11 min × 20 rounds ≈ **44 h** of
> pure LoRA fine-tuning that the federated design genuinely requires. Eval cuts get
> you under ~2 days; going below that means fewer experiments or a training-resident
> refactor (lever D).

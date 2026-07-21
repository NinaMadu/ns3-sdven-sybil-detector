# Stage-3 LLM-FL — completed evidence pack

Both supervisor comments are resolved. All numbers below are from the finished run
(seed 42, 5 rounds, Qwen2.5-1.5B). Paths are under `ml/llm/stage3_agents/`.

---

## Ablation D1 — the headline result

`runs/D1_results.md`

| Zone attacker % | Condition | MCC-V | Binary MCC | FPR | RC |
|---|---|---:|---:|---:|---:|
| 50/50/50/50 (homogeneous) | Local-Only | 0.7910 | — | — | — |
| 50/50/50/50 | LLM-FL | 0.7794 | 0.9972 | 0.0004 | 0.918 |
| 10/30/50/70 (heterogeneous) | Local-Only | 0.7666 | — | — | — |
| 10/30/50/70 | **LLM-FL** | **0.8025** | 0.9932 | 0.0004 | 0.919 |

**Interaction (the D1 conclusion):**

| Setting | Local-Only | LLM-FL | FL benefit |
|---|---:|---:|---:|
| Homogeneous | 0.791 | 0.779 | −0.012 (none — expected) |
| Heterogeneous | 0.767 | 0.802 | **+0.036 (clear)** |

Mechanism: under heterogeneity, local-only strands the attack-poor zone (10% attackers)
at MCC-V 0.708 while federation lifts all zones to one shared ~0.80 model.
Per-round curves: `runs/<exp>/history.json`.

---

## Issue 1 — LLM-FL executed (evidence)

- **Four-zone non-IID partition:** `data_fl/H0/zone_manifest.json`, `data_fl/Hmax/zone_manifest.json`
  (per-zone |D_r| = 5138, attacker fractions 50/50/50/50 and 10/30/50/70).
- **Eq 3.32 aggregation happened every round** — `runs/Hmax_llm_fl_seed42/round_005/global/a1/aggregation_manifest.json`:
  - 4 zones, each |D_r| = 5138, p_r = 0.25, **four distinct input hashes** (zones trained
    differently) → one aggregated `out_hash` a3fca86…, out size 18.516 MB.
- **Convergence tracked (Eq 3.73):** each `history.json` has the 5-round MCC-V curve and
  `kappa_conv` = "not converged by round 5" (curve still rising — reported honestly).
- **Per-round communication overhead** — `runs/Hmax_llm_fl_seed42/round_005/communication.json`:
  - Ω_LLM-FL = **55.4 MB** (analytical, Eq 3.71), Ω_full-weight = 7861 MB → **ζ_LoRA = 99.30 %**.
  - measured 4-RSU traffic = 444.4 MB/round (all uploads + downloads).

## Issue 2 — adapter size fixed (evidence)

- Each LoRA head = **18,516,456 bytes ≈ 18.5 MB**, bf16 A/B tensors only.
- `find runs final_models -name optimizer.pt -o -name 'checkpoint-*'` → **empty**
  (no optimizer state, no epoch checkpoints — the source of the old 307 MB).
- Arithmetic (`overhead.py`): 9,232,384 params/head × 2 bytes = 18.5 MB, matching the
  size a Qwen2.5-1.5B r=8 LoRA should be.

---

## Deployable FL models (for next work)

`promote_final.py` extracted the final global adapters + tokenizer + `deploy_config.json`:

```
final_models/H0_llm_fl_seed42/{a1,a2,a3}/     MCC-V 0.7794   (homogeneous)
final_models/Hmax_llm_fl_seed42/{a1,a2,a3}/   MCC-V 0.8025   (heterogeneous — recommended)
```

Each is a drop-in replacement for `consensus_infer` / the ns-3 real-time daemon.

## Reproduce the screenshots

```bash
cd ml/llm/stage3_agents
cat runs/D1_results.md
ls -la final_models/Hmax_llm_fl_seed42/a1/
find runs final_models -name optimizer.pt -o -name 'checkpoint-*'          # empty
../../.venv/bin/python overhead.py --adapter final_models/Hmax_llm_fl_seed42/a1
cat runs/Hmax_llm_fl_seed42/round_005/global/a1/aggregation_manifest.json
cat runs/Hmax_llm_fl_seed42/round_005/communication.json
cat runs/Hmax_llm_fl_seed42/history.json
```

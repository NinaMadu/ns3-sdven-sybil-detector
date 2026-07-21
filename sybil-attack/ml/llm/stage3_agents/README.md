# Stage-3 — LLM-FL (four-zone federated LoRA) for the three-agent detector

This stage exists to close the two gaps the supervisor raised about the Stage-2
LLM work (`../docs/LLM_FL/Supervisor_comment.txt`):

- **Issue 1 — LLM-FL was never executed.** Stage-2 is *centralized* LoRA training
  plus an *inference-time* three-agent vote. The paper claims LLM-FL as a named
  contribution with its own aggregation (Eq 3.32), convergence metric
  (`κ_conv^LLM-FL`, Eq 3.73) and overhead metric (`Ω_LLM-FL`, Eq 3.71), and
  Ablation D1 (LLM-FL vs Local-Only across inter-zone heterogeneity). None of that
  can be reported without actually running federation rounds. Stage-3 runs them.
- **Issue 2 — adapters were ~15× too large.** Stage-2 saved each head as ~307 MB
  (fp32 adapter + epoch checkpoints with 74 MB `optimizer.pt`). A Qwen2.5-1.5B
  r=8 LoRA is **9.23 M params → 18.5 MB in bf16**. Stage-3 saves *only* the bf16
  A/B tensors (`fedprox_train.save_bf16_adapter`), so `Ω`/`ζ_LoRA` are honest.

**Nothing in `stage2_agents/` is modified.** Stage-3 reuses Stage-2/`common` code
unchanged — the context vector (`build_context`), the class balancing
(`balance_train`), the three agent role prompts (`agents.py`), the LoRA recipe
(same base, r=8/α=16, 7 target modules, bf16), and the consensus arithmetic
(`consensus_infer`). The **only** thing added is the four-zone partition and the
federation loop.

## How this maps to Stage-2

```
Stage-2 (centralized):
  c_i[train] ──balance──► data_a*/train.jsonl ──train──► 1 pooled adapter / agent

Stage-3 (federated), the ONE added step is the partition:
  c_i[train] ─partition by zone─► zone_r ─balance(same fn)─► data_fl/<ep>/a*/zone_r/train.jsonl
                                                                   │
                                    per (zone,agent): FedProx LoRA train (same recipe)
                                                                   │
                                    Eq 3.32 controller aggregation ► 1 global adapter / agent / round
```

Same canonical input: `../common/context/c_i.parquet`. Same frozen `train/val/test`
split — **val and test are never partitioned**; they stay whole and shared, exactly
as in Stage-2.

## Data: the four zones

`partition_by_zone.py` splits only the 34,385 `train` rows into four disjoint,
equal-sized zones (|D_r| = 5,138 each) hitting each endpoint's target attacker
fraction. Attacker = `is_sybil==1`; rare attack types (e.g. `malicious_rsu`, ~120
rows) are stratified across zones so no zone loses a class for a reason unrelated
to the attacker-fraction manipulation.

Two report-defined endpoints:

| Endpoint | Zone attacker % | Meaning |
|---|---|---|
| `H0`   | 50 / 50 / 50 / 50 | homogeneous |
| `Hmax` | 10 / 30 / 50 / 70 | maximally heterogeneous |

Per-zone `|D_r|` and per-class counts are written to
`data_fl/<endpoint>/zone_manifest.json` — this is the non-IID verification table.

> **Note on the data prevalence.** The real `c_i` train pool is ~30 % attackers,
> so achieving 50 %/70 % attacker zones necessarily *sub-samples* legitimate rows;
> `partition_by_zone.py` reports the pool sizes and the exact per-zone counts. Class
> 6 `malicious_controller` has **zero** vehicle-tier windows by design (it is a
> control-plane attack — see `common/constants.py`), so it is absent from every
> zone; that is expected, not a partition artifact.

## Files

| File | Role |
|---|---|
| `fl_config.json` | **Frozen** single source of truth (base, LoRA, FedProx μ, rounds, endpoints, eval). |
| `fl_common.py` | Thin wrappers over Stage-2/`common` (context, balance, prompts) + paths. |
| `partition_by_zone.py` | **Step 1** — four-zone partition + shared frozen val/test + manifests. |
| `fedprox_train.py` | **Step 3** — local FedProx LoRA train for one (zone,agent); bf16-only save. |
| `aggregate_lora.py` | **Step 4** — Eq 3.32 sample-weighted A/B averaging + audit manifest. |
| `evaluate_round.py` | **Step 5** — Stage-2 consensus on frozen val; MCC-V, RC, per-class recall. |
| `overhead.py` | **Step 7** — Eq 3.71 analytical `Ω`/`ζ_LoRA` + measured 4-RSU bytes. |
| `run_federation.py` | **Steps 3–6** — one experiment (endpoint×condition×seed); Eq 3.73 stop. |
| `run_d1.sh` | **Step 8** — the four D1 experiments end to end, then collate. |
| `collate_d1.py` | Builds `runs/D1_results.md` / `.json` from all `history.json`. |
| `promote_final.py` | **Step 9 (optional)** — copy a finished FL run's final global adapters + tokenizer into `final_models/` for deployment. |

## How to run

The partition is already generated (`data_fl/`). To (re)generate:

```bash
cd ml/llm/stage3_agents
../../.venv/bin/python partition_by_zone.py
```

The federation is a **long GPU run** (each round trains 3 agents × 4 zones). Launch
under tmux so it survives logout (see the project's long-runs practice):

```bash
tmux new -s llmfl 'bash run_d1.sh'          # all 4 D1 experiments + collate
# or a single experiment:
../../.venv/bin/python run_federation.py --endpoint H0 --condition llm_fl --seed 42
```

Useful flags: `--resume` (skip rounds whose adapters already exist), `--rounds N`
(cap rounds), `--smoke` (tiny end-to-end sanity check — trains ~nothing, just
proves the plumbing).

### Config knobs (`fl_config.json`)

- `fedprox.mu` — proximal coefficient (Eq 3.33); `0.01` default, `0` = plain FedAvg-style.
- `federation.max_rounds` / `conv_window` / `conv_tol` — round budget and the Eq 3.73 stop.
- `partition.endpoints` — the heterogeneity vectors; add more only if the report defines them.
- `eval.theta_consensus` / `omega` — **frozen** so the D1 curve isn't confounded by moving calibration.

## Metrics (the D1 dependent variables)

- **MCC-V** — the vehicle-tier 7-class `MCC_macro` on the consensus variant vote
  (Eq 3.64–3.65). Reported as `final_mcc_macro` per experiment + per-class recall.
- **`κ_conv^LLM-FL`** — Eq 3.73: first round `T` whose newest 5-round validation
  `MCC_macro` window spans `< 1e-3`. If never satisfied, reported as
  `"not converged by round N"` (never silently replaced by the best round). For
  local-only, four per-zone curves + a summary curve are kept.
- **RC** — Eq 3.74 reasoning-evidence consistency. Implemented as a **documented
  proxy** (`evaluate_round.RC_SIGNATURES` maps each class to its expected evidence
  set `I*`, and `RC_VOCAB` maps evidence categories to reasoning keywords).
  ⚠ Confirm `I*` against the report's exact signature definition before quoting RC
  as a headline number — the mapping is deliberately isolated in one place to make
  that easy.
- **Overhead** — `Ω_LLM-FL` (Eq 3.71, analytical, one logical payload) **and**
  measured serialized bytes for the real four-RSU round (all 12 uploads + the
  global download to every zone). Both live in each round's `communication.json`.
  Reference values: `Ω_LLM-FL = 55.4 MB`, `Ω_full = 7,861 MB`, `ζ_LoRA = 99.30 %`.

## Output tree

```
runs/
  _init_seed42/{a1,a2,a3}/            shared round-0 init (same for both conditions)
  <endpoint>_<condition>_seed42/
    round_000/ ... round_NNN/
      local/zone_r/{a1,a2,a3}/        per-zone local adapters (18.5 MB each)
      global/{a1,a2,a3}/              Eq 3.32 output + aggregation_manifest.json
      metrics.json                    per-round MCC-V / RC / per-class recall
      communication.json              Ω (Eq 3.71) + measured bytes
    history.json                      full MCC_macro curve + κ_conv
  D1_results.md / .json               collated four-experiment table
```

`run_d1.sh` creates **four separate experiment folders** (2 endpoints × 2
conditions) — FL and non-FL never overwrite each other:

```
runs/H0_local_seed42/     runs/H0_llm_fl_seed42/
runs/Hmax_local_seed42/   runs/Hmax_llm_fl_seed42/
```

## Getting the trained FL model for downstream work

The federated model you deploy/reuse is the **last round's `global/` adapters of an
`llm_fl` experiment** — e.g. `runs/H0_llm_fl_seed42/round_005/global/{a1,a2,a3}/`.
Each `global/aX` is one fully-aggregated (Eq 3.32) LoRA head, same format as the
Stage-2 adapters. The `local` condition has **no single model** (four per-zone
adapter chains) — it is the D1 baseline, not a deployable artifact.

Those 18.5 MB adapters carry only bf16 A/B tensors (no tokenizer), so use the
promote helper to get a clean, deployable copy with the tokenizer restored:

```bash
../../.venv/bin/python promote_final.py --exp H0_llm_fl_seed42
# -> final_models/H0_llm_fl_seed42/{a1,a2,a3}/ + deploy_config.json
```

`deploy_config.json` mirrors `stage2_agents/consensus_config.json`, so the promoted
set is a drop-in replacement for consensus_infer / the ns-3 real-time daemon.

---

# Evidence pack for the supervisor

After `run_d1.sh` finishes, both issues are demonstrable from on-disk artifacts.
Below is exactly what to capture (terminal screenshots + the file each number
comes from). Everything is reproducible from the committed code and the manifests.

### Issue 2 — adapter size fixed (fast, do this first)

1. **Adapter is 18.5 MB, bf16, nothing else.** Screenshot:
   ```bash
   ls -la runs/H0_llm_fl_seed42/round_001/global/a1/
   find runs -name 'optimizer.pt' -o -name 'checkpoint-*'      # prints nothing
   ```
   Show: `adapter_model.safetensors` ≈ 18.5 MB, and the empty `find` (no optimizer
   state, no checkpoints). Contrast with the old
   `stage2_agents/adapters/qwen1_5b_a1/` (294 MB incl. `checkpoint-*/optimizer.pt`).
2. **Size is arithmetically correct.** Screenshot:
   ```bash
   ../../.venv/bin/python overhead.py --adapter runs/H0_llm_fl_seed42/round_001/global/a1
   ```
   Show `per_agent_lora_params_sum_r_dk = 9,232,384` → 18.5 MB in bf16, matching
   the supervisor's own hand-computation (~9.8 M params ≈ 19.6 MB).

### Issue 1 — LLM-FL actually executed

3. **Four-zone non-IID partition exists.** Screenshot the `partition_by_zone.py`
   table (per-zone `|D_r|` and per-class counts) and open
   `data_fl/Hmax/zone_manifest.json` showing attacker fractions 10/30/50/70 %.
4. **Real per-zone local training + Eq 3.32 aggregation happened.** Open
   `runs/H0_llm_fl_seed42/round_001/global/a1/aggregation_manifest.json` — show the
   four zones, `|D_r|=5138`, `p_r=0.25`, four **distinct `in_hash`** values (proves
   the zones trained differently) and one `out_hash` (the aggregated global).
5. **A convergence curve exists (Eq 3.73).** Open
   `runs/H0_llm_fl_seed42/history.json` — show `mcc_macro_curve` (one value per
   round) and `kappa_conv` / `kappa_conv_note`. This is the metric that "one round
   cannot produce"; it requires the five-round window.
6. **Overhead reported both ways.** Screenshot
   `runs/H0_llm_fl_seed42/round_001/communication.json` — analytical `Ω_LLM-FL`,
   `ζ_LoRA = 99.30 %`, and the measured 4-RSU bytes, with the counting convention.

### The D1 result (the headline)

7. **The four-experiment table.** Screenshot the terminal output of
   `collate_d1.py` and open `runs/D1_results.md`. It has one row per
   (endpoint × condition), each with MCC-V, `κ_conv`, RC, binary MCC, FPR. Point out
   the intended reading: **does LLM-FL beat Local-only more as zones diverge
   (Hmax) than when homogeneous (H0)?** — that interaction is the D1 conclusion.
8. **Per-zone honesty.** Note in `D1_results.md` the per-zone `κ_conv` for
   local-only, and in each `metrics.json` the per-class recall (so a strong global
   number cannot hide the `malicious_rsu` thin-class or the structurally-absent
   `malicious_controller`).

### One-paragraph status line to give the supervisor

> The four-zone LLM-FL flow is now executed: `train` is partitioned into four RSU
> zones at the two D1 heterogeneity endpoints (50/50/50/50 and 10/30/50/70), each
> zone trains local FedProx LoRA adapters from a shared init using the unchanged
> Stage-2 recipe, and the SDN controller aggregates them every round by Eq 3.32.
> We report MCC-V, `κ_conv^LLM-FL` (Eq 3.73, five-round window) and RC for both
> Local-only and LLM-FL, plus analytical (Eq 3.71) and measured per-round
> overhead. Adapters are now saved as bf16 LoRA A/B tensors only (18.5 MB/head,
> ζ_LoRA = 99.3 %), fixing the earlier 307 MB inflation.

## Caveats to state honestly (do not hide these)

- **RC `I*` mapping is a proxy** pending confirmation against the report's exact
  signature set (isolated in `evaluate_round.RC_SIGNATURES`).
- **Endpoint mean.** The report says both endpoints share a 50 % mean, but
  `[10,30,50,70]` averages to 40 %. Stage-3 uses the report's literal vectors and
  flags this; adjust `fl_config.partition.endpoints` if the report intends a
  different Hmax vector.
- **`malicious_controller` (class 6)** never appears at the vehicle tier, so its
  recall is reported as 0 across all conditions — a data-structure fact, not an
  FL failure.

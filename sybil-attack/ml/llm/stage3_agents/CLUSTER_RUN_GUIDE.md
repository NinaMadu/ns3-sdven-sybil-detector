# Running the LLM-FL convergence study on the cluster

Goal: extend the federation past 5 rounds until Equation 3.73 actually triggers, so
**κ_conv^LLM-FL** can be reported as a measured number instead of "not converged".

Nothing in the completed 5-round study is modified. This run uses a **separate
config** (`fl_config_convergence.json`) and writes to its own `runs/` tree on the
cluster, so the existing results stay exactly reproducible.

---

## 1. What changes in this run (and why)

Two differences from the 5-round study — everything else (base model, LoRA rank,
FedProx μ, zone partition, batch, epochs, evaluation) is byte-identical:

| Setting | 5-round study | Convergence run | Why |
|---|---|---|---|
| `lr_decay_per_round` | none (1.0) | **0.7** | Previously every round restarted the cosine schedule at the full 2e-4, so the model never globally annealed and could not plateau. `lr_t = 2e-4 × 0.7^(t-1)` lets it settle. |
| `max_rounds` | 5 | **12** | Eq 3.73 needs a five-round window; 5 rounds cannot produce one. |

`conv_window = 5` and `conv_tol = 1e-3` are the paper's values and are **not**
relaxed. The run stops automatically the moment the criterion is met.

---

## 2. What to bring from here

The cluster is a **separate machine with no connection back to here** — so
everything travels as files you copy once (scp / rsync / USB). Two things move:
a bundle, and the base model.

### a) The bundle — use `llmfl_cluster_bundle_FULL.tar.gz` (45 MB) ← RECOMMENDED

This is self-contained: code + the dataset + the **already-partitioned zone data**.
Nothing is regenerated, nothing can drift.

```
llm/common/context/c_i.parquet     the dataset itself (25 MB, 49,569 windows)
llm/common/*.py                    constants, context builder, eval helpers
llm/stage2_agents/agents.py        the three agent role prompts
llm/stage2_agents/consensus_infer.py   Eq 3.22 consensus math
llm/stage3_agents/*.py|.json|.sh   all Stage-3 code + both configs + docs
llm/stage3_agents/data_fl/         READY-TO-TRAIN zone data:
                                     H0/  Hmax/  (4 zones x 3 agents each)
                                     shared/     (frozen val + test sets)
```

With this bundle you can **skip step 5** (partition regeneration) entirely.

> There is also a smaller `llmfl_cluster_bundle.tar.gz` (22 MB) that omits
> `data_fl/` and regenerates it on the cluster. Both contain the dataset —
> `data_fl/` is only the same data expanded into chat-format JSONL (3 agents ×
> 4 zones × 2 endpoints + class balancing), which is why it is bigger. The 45 MB
> FULL bundle is worth it to remove any regeneration risk. Rebuild either with
> `bash make_cluster_bundle.sh`.

### b) The base model — Qwen2.5-1.5B-Instruct (~2.9 GB)

Two options:

- **Download on the cluster** (simplest, if compute nodes or a login node have
  internet): nothing to copy, it fetches on first use.
- **Copy your local HF cache** (if the cluster is offline):
  ```bash
  rsync -av ~/.cache/huggingface/hub/models--Qwen--Qwen2.5-1.5B-Instruct/ \
            <user>@<cluster>:~/.cache/huggingface/hub/models--Qwen--Qwen2.5-1.5B-Instruct/
  ```
  then export `HF_HUB_OFFLINE=1` in the job script.

### c) What you do NOT need to copy

| Not copied | Size | Why |
|---|---|---|
| `runs/` | ~4.9 GB | The previous 5-round outputs. This is a clean run with the new schedule, so they are not inputs. Keep them here as the record of the completed study. |
| `final_models/` | ~110 MB | Outputs of the previous run, not inputs. |
| `figures/` | small | Regenerated from the new results by `plot_convergence.py`. |

**Total transfer: 45 MB** (plus the 2.9 GB model only if the cluster has no internet).

### How to copy it

```bash
# from THIS machine
scp llmfl_cluster_bundle_FULL.tar.gz <user>@<cluster>:~/
```
Or put it on a USB drive — it is one 45 MB file. Nothing else needs to move, and
the cluster never contacts this machine again.

---

## 3. Environment on the cluster

Python **3.9** with these exact versions (what the local run used):

```
torch          2.8.0+cu128
transformers   4.57.6
peft           0.17.1
trl            0.24.0
datasets       4.5.0
safetensors    0.7.0
scikit-learn   1.6.1
pandas         2.3.3
numpy          2.0.2
matplotlib     3.9.4
```

Setup — `requirements.txt` is in the bundle:

```bash
module load python/3.9 cuda            # adapt to your cluster's module names
python -m venv ~/llmfl-venv
source ~/llmfl-venv/bin/activate
pip install --upgrade pip

# 1) torch FIRST and separately — the wheel depends on the cluster's CUDA driver
nvidia-smi                                     # check the CUDA version
pip install torch==2.8.0 --index-url https://download.pytorch.org/whl/cu128

# 2) everything else (CUDA-independent)
cd ~/llmfl/llm/stage3_agents
pip install -r requirements.txt
```

> If the cluster's CUDA differs from 12.8, swap the index-url (`cu121`, `cu124`, …).
> Everything in `requirements.txt` is CUDA-independent and pinned to the versions
> the 5-round study used, so the two runs stay comparable.

Verify before submitting anything:

```bash
python -c "import torch, transformers, peft, trl; \
print('torch', torch.__version__, '| CUDA available:', torch.cuda.is_available()); \
print('transformers', transformers.__version__, '| peft', peft.__version__, '| trl', trl.__version__)"
```
`CUDA available: True` is the one that matters.

GPU requirement: **one GPU with ≥ 24 GB** per concurrent experiment (the local run
peaked around 24–28 GB on a 32 GB card). A 40/80 GB A100 or H100 is comfortable.

---

## 4. Unpack

```bash
mkdir -p ~/llmfl && cd ~/llmfl
tar -xzf ~/llmfl_cluster_bundle_FULL.tar.gz    # creates llm/
cd llm/stage3_agents
ls data_fl                                     # -> H0  Hmax  shared   (data is here)
```

---

## 5. Partition — SKIP THIS if you used the FULL bundle

The FULL bundle already contains `data_fl/`, so there is nothing to do; go to step 6.

Only if you used the small bundle, regenerate it:

```bash
python partition_by_zone.py --config fl_config_convergence.json
```

Check the printed tables against these — they must match **exactly**, which proves
the cluster is training on the identical zones:

```
equal zone_size = 5138

H0   (homogeneous)     every zone: 5138 rows, 50.0% attackers
     per zone: legit 2569 | outsider 868 | sim 1056 | nonsim 330 | indirect 285 | mal_rsu 30

Hmax (heterogeneous)   every zone: 5138 rows
     zone1 10.0%  legit 4624 | outsider 174 | sim 211 | nonsim  66 | indirect  57 | mal_rsu  6
     zone2 30.0%  legit 3597 | outsider 520 | sim 634 | nonsim 198 | indirect 171 | mal_rsu 18
     zone3 50.0%  legit 2569 | outsider 868 | sim 1056| nonsim 330 | indirect 285 | mal_rsu 30
     zone4 70.0%  legit 1541 | outsider 1215| sim 1479| nonsim 462 | indirect 399 | mal_rsu 42
```

If anything differs, stop — the numpy/pandas versions differ and you should copy
`data_fl/` from here instead (505 MB) rather than regenerate.

---

## 6. Smoke test (5 minutes — always do this first)

```bash
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
python run_federation.py --config fl_config_convergence.json \
       --endpoint H0 --condition llm_fl --seed 42 --smoke
```

Proves the whole chain works: init → 12 local trainings → Eq 3.32 aggregation →
evaluation → `history.json`. Then delete the smoke output:

```bash
rm -rf runs/H0_llm_fl_seed42 runs/_init_seed42
```

---

## 7. Run the four experiments — **in parallel, one GPU each**

This is the big cluster win. The four experiments are **completely independent**, so
they can run simultaneously on four GPUs instead of sequentially. That turns a
~5-day serial run into roughly **2 days**.

Example SLURM array job (adapt partition/account/module names to your cluster):

```bash
#!/bin/bash
#SBATCH --job-name=llmfl
#SBATCH --array=0-3
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=72:00:00
#SBATCH --output=logs/llmfl_%a.out

source ~/llmfl-venv/bin/activate
cd ~/llmfl/llm/stage3_agents
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false

EP=(H0     H0      Hmax   Hmax)
CD=(local  llm_fl  local  llm_fl)

python run_federation.py --config fl_config_convergence.json \
       --endpoint "${EP[$SLURM_ARRAY_TASK_ID]}" \
       --condition "${CD[$SLURM_ARRAY_TASK_ID]}" \
       --seed 42 --resume
```

Save as `submit_llmfl.sh`, then `sbatch submit_llmfl.sh`.

**If you only get one GPU**, run them sequentially instead — the existing driver
already does this: `bash run_d1.sh` (edit it to pass `--config fl_config_convergence.json`).

### Expected wall-clock

Per round: ~2.2 h of training (12 LoRA fine-tunes) + evaluation (~0.45 h for
`llm_fl`, ~1.8 h for `local`, which evaluates four zones).

| Experiment | Per round | 12 rounds (worst case) |
|---|---:|---:|
| `*_llm_fl` | ~2.6 h | ~31 h |
| `*_local` | ~4.0 h | ~48 h |

In parallel the total is bounded by the slowest: **~2 days**, and likely less —
with LR decay the run should trigger Eq 3.73 and **stop early**, around round 8–10.
A faster cluster GPU shortens this further.

`--resume` means a killed or timed-out job can simply be resubmitted; completed
rounds are skipped and, with the new metrics caching, already-evaluated rounds are
not re-generated either.

---

## 8. Monitor

```bash
squeue -u $USER                                  # jobs running?
tail -f logs/llmfl_3.out                         # live progress
grep -E "^  round |converged|=== done" logs/llmfl_*.out
find runs -name history.json                     # 4 files = all finished
```

The line to watch for is `Eq 3.73 converged: kappa_conv = round N` — that is the
number this whole run exists to produce.

---

## 9. When it finishes — collate, promote, plot

```bash
python collate_d1.py                                     # -> runs/D1_results.md
python promote_final.py --exp Hmax_llm_fl_seed42         # deployable FL model
python promote_final.py --exp H0_llm_fl_seed42
python plot_convergence.py                               # -> figures/*.png
```

---

## 10. What to bring BACK from the cluster

Small and sufficient for the report and the evidence pack:

```bash
tar -czf llmfl_results.tar.gz \
    runs/*/history.json \
    runs/*/round_*/metrics.json \
    runs/*/round_*/communication.json \
    runs/*/round_*/global/*/aggregation_manifest.json \
    runs/D1_results.md runs/D1_results.json \
    figures/
```
That is a few MB. Additionally bring the promoted models if you want to deploy them:

```bash
tar -czf llmfl_models.tar.gz final_models/        # ~110 MB
```

Leave the full `runs/` tree (several GB of intermediate adapters) on the cluster.

---

## 11. Adding the result to the report

The convergence run changes **three** things in Chapter 5. Everything else you have
already written stays as it is.

### §5.2 (Ablation D1) and §5.3.7 — replace the κ_conv entry

Where the table currently reads *"not converged by round 5"*, put the measured
value from `runs/<exp>/history.json` → `kappa_conv`:

> κ_conv^LLM-FL = **N** rounds — the first round at which the validation MCC_macro
> varied by less than 10⁻³ across five consecutive rounds (Eq 3.73).

Report it for each condition; D1 requires the same round budget in both, which the
config guarantees.

### The convergence figure — regenerate, don't redraw

`plot_convergence.py` reads the new `history.json` files, so the two figures update
automatically with the longer curves:

- `fig_convergence_curves.png` — per-round MCC-V progression (this is the "per-round
  MCC progression curve" the supervisor asked for), now running to convergence.
- `fig_convergence_gap.png` — the round-to-round change against the 10⁻³ tolerance,
  now visibly crossing below the line at κ_conv.

Suggested caption:

> **Figure X.** Per-round validation MCC-V for the four Ablation D1 conditions under
> the federated schedule with round-wise learning-rate decay. The Eq 3.73 criterion
> (five consecutive rounds within 10⁻³) is first satisfied at round N, giving
> κ_conv^LLM-FL = N.

### Methodology — one sentence, stated plainly

Add to the LLM-FL setup description:

> Local training uses a round-wise learning-rate decay, lr_t = lr₀·γ^(t-1) with
> γ = 0.7, so that the federation anneals and the convergence criterion of
> Equation 3.73 is well-posed; all other hyperparameters are unchanged.

This is worth stating explicitly rather than burying — it is a legitimate and
standard federated-learning choice, and it is the reason a κ_conv exists at all.

### Keep the 5-round study

Do not delete it. It is the honest record of the original configuration, and the
comparison (no convergence without decay → convergence with it) is itself a useful
methodological observation if a reviewer asks why the schedule changed.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| CUDA OOM | Lower `local_train.batch` to 4 and raise `grad_accum` to 4 in `fl_config_convergence.json` (same effective batch). |
| Job hits the time limit | Just resubmit — `--resume` continues from the last completed round. |
| Model download fails | Copy the HF cache (§2b) and set `HF_HUB_OFFLINE=1`. |
| Partition tables differ from §5 | numpy/pandas version mismatch — copy `data_fl/` from the local machine instead. |
| Still not converged at round 12 | Raise `max_rounds`, or lower `lr_decay_per_round` to 0.6 for faster annealing. Do **not** raise `conv_tol` — that changes a paper-defined constant. |

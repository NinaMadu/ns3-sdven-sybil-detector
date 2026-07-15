# `sybil-attack/ml/` — organization

Reorganized 2026-07-13. One place for all experiments: the six ML analyzers, the
Eq 3.18/3.20 fusion, and the LLM decision tier (Stage 1 and Stage 2).

```
ml/
├── analyzers/                  # the experiments: one folder per detector
│   ├── rssi_cnn/               #   RSSI 1-D CNN (federated) — v2, v3
│   ├── temporal_gru/           #   temporal GRU (hier-FL) — v3, v4
│   ├── temporal_xgb_rsu/       #   RSU temporal XGBoost (7-class)
│   ├── rssi_xgb_rsu/           #   RSU RSSI XGBoost (7-class)
│   ├── vehicle_trust/          #   vehicle trust MLP (trust_v2_lib.py) + notebooks
│   └── rsu_trust/              #   RSU trust
│        each: notebooks/  (the .ipynb, tracked)   outputs/  (weights, per-model
│                                                             parquet, metrics — IGNORED)
│
├── fusion/                     # Eq 3.18 head + Eq 3.19/3.20 ensemble + spine
│   ├── train_fusion_head.py    #   Eq 3.18  ŷ_i
│   ├── rsu_ensemble.py         #   Eq 3.19/3.20  ŷ_ens  (λ grid-search)
│   ├── mobility_tokens.py      #   v_rel, ρ_c, Δt_sync
│   ├── identity_manifest.py    #   shared split_map + raw-log reader
│   ├── spine/                  #   THE seam the LLM consumes (IGNORED):
│   │                           #     {temporal,rssi,trust}_vehicle_tier.parquet, split_map.parquet
│   └── outputs/                #   fusion_head, ensemble_yhat, ensemble_lambdas, mobility (IGNORED)
│
├── llm/                        # the LLM decision tier
│   ├── common/                 #   shared across stages
│   │   ├── constants.py        #     THE path hub + 7-class taxonomy + JOIN_KEY
│   │   ├── build_context_vector.py   #  Eq 3.31 assembler → context/c_i.parquet
│   │   ├── build_llm_dataset.py       #  c_i row → chat record (+ balance)
│   │   ├── eval_fusion.py             #  JSON parse + scorecard helpers
│   │   ├── train_lora_generic.py      #  the SFT trainer (both stages)
│   │   └── context/c_i.parquet        #  (IGNORED)
│   ├── stage1_single_head/     #   Qwen2.5-0.5B · ONE LoRA head · r16/α32
│   │   ├── data/ data_stage0/          (IGNORED)
│   │   ├── adapters/  qwen0_5b_v2, qwen0_5b_stage0      (IGNORED)
│   │   ├── bakeoff/   qwen0_5b, llama1b, qwen1_5b       (IGNORED)
│   │   └── scorecards/  qwen0_5b_v2.json …              (IGNORED)   MCC 0.9969
│   └── stage2_agents/          #   Qwen2.5-1.5B · 3 agents + Eq 3.22 · r8/α16
│       ├── agents.py · build_agent_datasets.py · consensus_eval.py
│       ├── data_a1/ data_a2/ data_a3/                  (IGNORED)
│       ├── adapters/  qwen1_5b_a1, _a2, _a3            (IGNORED)
│       └── scorecards/  stage2_consensus.json …        (IGNORED)   consensus MCC 0.9991
│
├── _archive/                   # superseded/duplicate trees (IGNORED, not deleted)
└── .venv/                      # the one Python env (IGNORED)
```

## The one seam

Everything downstream of `llm/common/context/c_i.parquet` is pure LLM; everything
upstream is analyzers + fusion. `fusion/spine/` is the single promotion point — the
vehicle-tier parquets the LLM actually consumes. Promote a new detector version by
copying its parquet into `fusion/spine/` (mind the JOIN_KEY columns), then rebuild
c_i. (This is the step that silently used stale detectors before the reorg.)

## Path hub

`llm/common/constants.py` defines every path: `SPINE_DIR`, `FUSION_DIR`,
`ANALYZERS_DIR`, the three `*_PARQUET`, `SPLIT_MAP`, and the RSU-XGB inputs. Change
a location there and the whole pipeline follows. `fusion/*.py` add `llm/common` to
`sys.path`; `fusion/identity_manifest.py` points at `fusion/spine` + `fusion/outputs`.

## Run

```bash
commands/run_stage2_llm.sh all      # ensemble → datasets → train → eval (Stage 2)
commands/run_stage2_llm.sh eval     # just Eq 3.22 consensus (does NOT auto-run after `train`)
```
Always in `ml/.venv` with `TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg`.

## Git

Source (`*.py`, `*.ipynb`, `*.md`, `*.sh`) is tracked; weights, adapters, datasets,
`context/`, `spine/`, `outputs/`, `_archive/`, `.venv/` are ignored (root `.gitignore`).

## Caveat — notebook internal paths

Notebooks were relocated next to their outputs, but their *internal* read/write paths
were not rewritten. Re-running a notebook may still target an old path (e.g.
`ml/Outputs_RSSI`) or write to its own `outputs/` — update the path cell (or run with
`cwd` = the analyzer folder) before re-executing. The fusion/LLM Python pipeline paths
ARE all updated and verified.

## Backup

Pre-reorg hardlink snapshot: `ns-3.35/_ml_migration_backup_20260713/` (all 8 adapter
sets, spine, v4/v3 outputs). Delete once the new layout is confirmed.

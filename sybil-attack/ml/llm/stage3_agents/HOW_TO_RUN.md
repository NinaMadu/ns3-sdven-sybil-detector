# How to run Stage-3 LLM-FL — launch, monitor, finish, next steps

A step-by-step operational guide. For the *what/why*, see `README.md`. All commands
are run from this directory:

```bash
cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35/sybil-attack/ml/llm/stage3_agents
```

`PY` below means the project venv python: `../../.venv/bin/python`.

---

## 0. One-time pre-flight (fast, ~1 min)

Confirm the partition exists (it already does; this just re-verifies / regenerates):

```bash
../../.venv/bin/python partition_by_zone.py
```

You should see the two per-zone tables (H0 = 50/50/50/50, Hmax = 10/30/50/70) and
`data_fl/H0/zone_manifest.json` + `data_fl/Hmax/zone_manifest.json`. If you see those,
you're ready.

---

## 1. Launch the full D1 run (under tmux)

The run is long (roughly 8–17 hours for all four experiments at 5 rounds). Launch it
in a **detached tmux session** so it survives closing VS Code / SSH:

```bash
tmux new -s llmfl 'bash run_d1.sh 2>&1 | tee runs/run_d1.out'
```

- `tmux new -s llmfl` creates a session named `llmfl`.
- `tee runs/run_d1.out` also writes all output to a file you can read anytime.
- The session keeps running after you **detach**: press `Ctrl-b` then `d`.
  (That is: hold Ctrl, press b, release both, then press d.)

That single command runs everything end-to-end:
partition → `H0_local` → `H0_llm_fl` → `Hmax_local` → `Hmax_llm_fl` → collate.

> Tip: to run just one endpoint first (halves the time), use `bash run_d1.sh H0`.

---

## 2. Check progress from time to time

You can peek anytime, from a normal terminal (no tmux needed):

**a) Re-attach to watch it live:**
```bash
tmux attach -t llmfl
```
Detach again with `Ctrl-b` then `d`. (Do NOT press `Ctrl-c` inside — that kills the run.)

**b) Tail the log without attaching:**
```bash
tail -n 40 runs/run_d1.out
```
Look for lines like:
```
round 2 mcc_macro=0.87 binary_mcc=0.95 fpr=0.01 rc=0.9
```
Each such line = one finished round. `round N mcc_macro=...` for `llm_fl`;
`round N per-zone mcc_macro={...} summary=...` for `local`.

**c) See which experiments/rounds are already done on disk:**
```bash
ls -d runs/*_seed42/ 2>/dev/null
find runs -name history.json          # each finished experiment writes one
find runs -name 'round_*' -type d | sort
```

**d) Confirm it's still actually running:**
```bash
pgrep -af "run_federation|fedprox_train" | head
nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv
```
If you see a python process and non-zero GPU use, it's working.

**e) Rough progress math:** 4 experiments × 5 rounds = 20 rounds total; each round
prints one summary line. Count the `round ` lines done vs 20 to gauge how far along
you are:
```bash
grep -c "^  round " runs/run_d1.out
```

---

## 3. How to know it's DONE

The run is finished when you see this near the end of the log:

```
=== collating D1 table ===
=== D1 complete -> .../runs/D1_results.md ===
```

Confirm concretely:

```bash
cat runs/D1_results.md                     # the four-row D1 table exists
find runs -name history.json | wc -l       # should print 4
pgrep -af run_federation || echo "no run process -> finished"
```

When `D1_results.md` exists **and** there is no `run_federation` process, it's done.
You can then close the tmux session:
```bash
tmux kill-session -t llmfl
```

---

## 4. After it finishes — what to run next

### 4a. Look at the headline result
```bash
cat runs/D1_results.md
```
This is the Ablation D1 table: MCC-V, κ_conv, RC, binary MCC, FPR for
LLM-FL vs Local-only at both heterogeneity endpoints.

### 4b. Extract the FL models you'll use downstream
The models you keep are the **final global adapters of the two `llm_fl` runs**.
Promote them into clean, deployable folders (this also restores the tokenizer):

```bash
../../.venv/bin/python promote_final.py --exp H0_llm_fl_seed42
../../.venv/bin/python promote_final.py --exp Hmax_llm_fl_seed42
```

Result:
```
final_models/H0_llm_fl_seed42/{a1,a2,a3}/   + deploy_config.json
final_models/Hmax_llm_fl_seed42/{a1,a2,a3}/ + deploy_config.json
```
`deploy_config.json` is drop-in compatible with `consensus_infer` / the ns-3 daemon.
(Homogeneous `H0` is usually the one to deploy; keep `Hmax` for the heterogeneity
analysis. Deploy whichever your next step needs.)

### 4c. Generate the evidence pack for the supervisor
Everything the supervisor asked to see is now on disk. Capture these (see
`README.md` → "Evidence pack" for the full checklist and what each proves):

```bash
# Issue 2 (adapter size fixed):
ls -la runs/H0_llm_fl_seed42/round_005/global/a1/
find runs -name 'optimizer.pt' -o -name 'checkpoint-*'          # prints nothing
../../.venv/bin/python overhead.py --adapter runs/H0_llm_fl_seed42/round_005/global/a1

# Issue 1 (LLM-FL executed):
cat data_fl/Hmax/zone_manifest.json                              # non-IID zones
cat runs/H0_llm_fl_seed42/round_005/global/a1/aggregation_manifest.json   # Eq 3.32
cat runs/H0_llm_fl_seed42/history.json                          # κ_conv curve
cat runs/H0_llm_fl_seed42/round_005/communication.json          # Ω + measured bytes

# The D1 result:
cat runs/D1_results.md
```

> Note: the exact round number in these paths is the last round that ran — usually
> `round_005`. If a run converged earlier and stopped, use the highest `round_*`
> present (`ls -d runs/H0_llm_fl_seed42/round_*`).

---

## If something goes wrong

- **It stopped early / errored.** Read the tail of `runs/run_d1.out` and the
  experiment's own `runs/<exp>/run.log` for the failing subprocess.
- **Re-run safely.** `run_d1.sh` calls `run_federation.py --resume`, so relaunching
  the same command **skips rounds already completed** and continues where it left
  off. You will not lose finished rounds.
- **GPU out of memory.** Nothing else should be using the GPU during the run; check
  with `nvidia-smi`. Lower `local_train.batch` in `fl_config.json` if needed.
- **Want it shorter.** Run one endpoint (`bash run_d1.sh H0`) or lower
  `federation.max_rounds` in `fl_config.json`.

# Dataset-Generation Modes 8 & 9 — Full Reference

Modes **8** (`ATTACK_ZONE_CONCURRENT`) and **9** (`ATTACK_SEQUENTIAL_ALL6`) were added in
commit `cb01d55` ("feat: new attack run mode 8 and 9"). Both exist to generate
**labelled ML/FL training datasets** from the `Sybil-Developing-Improved` simulator.
This document is the authoritative reference for what they do, every parameter,
how to customize them, and the exact commands to run.

Source of truth: [`scratch/sybil_types.h`](../../scratch/sybil_types.h),
[`scratch/sybil_attacks.h`](../../scratch/sybil_attacks.h),
[`scratch/Sybil-Developing-Improved.cc`](../../scratch/Sybil-Developing-Improved.cc).

---

## 1. The attack-type family

```
0  ATTACK_NONE                            baseline / no attack
1  ATTACK_OUTSIDER                        outsider Sybil (fabricated IDs)
2  ATTACK_INSIDER_DIRECT_SIMULTANEOUS     multiple fake IDs broadcast at once
3  ATTACK_INSIDER_DIRECT_NON_SIMULTANEOUS fake IDs rotated over time
4  ATTACK_INSIDER_INDIRECT                fake IDs injected via a relay node
5  ATTACK_MALICIOUS_RSU                   compromised RSU fabricates reports
6  ATTACK_MALICIOUS_SDN_CONTROLLER        compromised controller injects records
7  ATTACK_SEQUENTIAL_1234                 attacks 1→2→3→4 back-to-back (older dataset mode)
8  ATTACK_ZONE_CONCURRENT                 types 1–6 concurrent, one per geographic zone
9  ATTACK_SEQUENTIAL_ALL6                 attacks 1→2→3→4→5→6 back-to-back (full 7-class dataset)
```

| | **Mode 9 — Sequential-All-6** | **Mode 8 — Zone-Concurrent** |
|---|---|---|
| Idea | One attack type at a time, all six in sequence over time | Different attack types running at the same time in different map zones |
| Time axis | 6 phases, one type per phase | All types active for the whole run |
| Attacker % | **Global** (`sybil_attack_percentage`), optionally ramped over time | **Per zone** (`attack_pct` column in the zone CSV) |
| Requires | nothing extra | a `zone_profiles.csv` **and** `--N_Controllers=<#zones>` |
| Use case | Clean single-label-per-window training data, all 7 classes | Federated-learning data where each zone/client sees a different attack |

**Two equivalent ways to select each mode** (they auto-sync in `main()`):

```
--sybil_attack_type=9   ⇔   --datasetMode=sequential_all6
--sybil_attack_type=8   ⇔   --datasetMode=zone_concurrent
```

Set either one; the other is filled in automatically.

---

## 2. Quick start

Build once (from the ns-3.35 root):

```bash
cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35
./waf build
```

**Mode 9 — one run:**

```bash
cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35
mkdir -p sybil-attack/outputs/seq6_demo
./waf --run "Sybil-Developing-Improved \
  --mobility_mode=5 --sumoAutoConfig=true --routing_test=false \
  --sybil_attack_enabled=true --datasetMode=sequential_all6 \
  --sybil_attack_percentage=50 --sybilFanoutRange=2,5 \
  --simTime=60 --beaconInterval=0.1 \
  --seed=1 --runId=seq6_s1 --scenarioId=seq6 \
  --outputDir=sybil-attack/outputs/seq6_demo"
```

**Mode 8 — one run (note `--N_Controllers=4`, see §7):**

```bash
cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35
mkdir -p sybil-attack/outputs/zone_demo
./waf --run "Sybil-Developing-Improved \
  --mobility_mode=5 --sumoAutoConfig=true --routing_test=false --N_Controllers=4 \
  --sybil_attack_enabled=true --datasetMode=zone_concurrent \
  --zoneProfiles=sybil-attack/inputs/zone_profiles_default.csv \
  --sybilFanoutRange=2,5 \
  --simTime=120 --beaconInterval=0.1 \
  --seed=1 --runId=zone_default_s1 --scenarioId=zone_concurrent \
  --outputDir=sybil-attack/outputs/zone_demo"
```

---

## 3. Base parameters these modes depend on

These are **not** new, but modes 8/9 will not behave correctly without the right values.

| Flag | Default | Must be for modes 8/9 | Notes |
|---|---|---|---|
| `--sybil_attack_enabled` | `false` | **`true`** | Master on/off. Nothing happens if false. |
| `--sybil_attack_type` | `0` | `8` or `9` | Or set `--datasetMode` instead (auto-syncs). |
| `--mobility_mode` | `2` | **`5`** | SUMO Kuala Lumpur trace; gives real positions + zones. |
| `--sumoAutoConfig` | `true` | `true` | Auto-sets `N_Vehicles`/`N_RSUs` from the trace. |
| `--routing_test` | **`true`** | **`false`** | If left true it forces a 3-veh/2-RSU test net and clamps `simTime≤12`. Always pass `false`. |
| `--N_Controllers` | `1` | **`=#zones`** (mode 8) | **Not** auto-derived from the trace. Mode 8's 4-zone profiles need `4`. See §7. |
| `--beaconInterval` | `1.0` | `0.1` recommended | Beacon period; `0.1` gives ~10× denser rows. |
| `--rsuReportInterval` | `1.5` | (default fine) | RSU→controller period; sets type-5/6 injection cadence. |
| `--simTime` | `12.0` | **`>12`** | See §6 — the override gotcha. Mode 9 = per-phase; mode 8 = total. |
| `--sybil_attacker_level` | `2` | 1–4 | Sophistication. **Controls the type-5/6 phantom count** and the fanout fallback (see §5). |
| `--sybil_attack_percentage` | `25` | your choice | Global attacker % (mode 9). **Ignored for vehicle selection in mode 8** (zone CSV wins). |
| `--outputDir` | `sybil-attack/outputs` | any existing dir | Must exist — `mkdir -p` it first. |
| `--solution_mode` | none | any | Detection mode. Does **not** affect the dataset — labels are ground truth. |
| `--txPower` | (build default) | optional | Raise for denser connectivity if the trace is sparse. |

---

## 4. New dataset parameters (added by this commit)

All parsed in `main()` after `cmd.Parse`.

| Flag | Default | Applies to | Meaning |
|---|---|---|---|
| `--datasetMode` | `""` (empty = legacy) | 8 & 9 | `sequential_all6` \| `zone_concurrent`. Auto-syncs with `--sybil_attack_type`. |
| `--seed` | `42` | 8 & 9 | Seed for attacker selection and fanout draws. **Reproducibility knob.** |
| `--runId` | auto: `<scenarioId>_s<seed>` | 8 & 9 | String stamped into every dataset CSV row (`run_id` column). |
| `--scenarioId` | auto: `<datasetMode>` or `baseline` | 8 & 9 | Label written to `run_meta.json` and the `scenario_id` column. |
| `--sybilFanoutRange` | `2,10` | 8 & 9 | `min,max` phantom fanout per attacker. Clamped to `[1,20]`. Drawn per attacker with `--seed`. **But capped hard per attack type — see §5.** |
| `--sybilIdsPerAttacker` | `0` (=use range) | 8 & 9 | Fixed fanout for every attacker; if `>0` it overrides `--sybilFanoutRange`. Clamped to `≤20`. |
| `--intensitySchedule` | `""` → behaves as `fixed` | **9 only** | `fixed` (constant %) or `stepped` (ramp % within each phase). |
| `--intensityLadder` | `20,40,60,80,100` | **9 only** | Percentages the `stepped` ramp climbs through, one per sub-window. |
| `--intensitySubwindows` | `5` | **9 only** | Number of equal sub-windows each phase is split into for the ramp. |
| `--zoneProfiles` | `""` | **8 only** | Path to the zone CSV. **Required** for mode 8 — the run aborts (returns 1) if missing or empty. |

---

## 5. How attackers and fanout actually work (read this — it's the surprising part)

### 5.1 Who becomes an attacker

- **Mode 9:** global count-based selection in `DeclareAttackers()`.
  `nAttackers = N_Vehicles * sybil_attack_percentage / 100`, chosen by a deterministic
  hash rank `(i*37+11)%100`. The **same attacker set** is reused across phases 1–4.
  For phase 5, `N_RSUs * sybil_attack_percentage / 100` RSUs are marked malicious
  (**forced to ≥1** so phase 5 always has data). For phase 6, the controller is
  **always** malicious regardless of percentage.
- **Mode 8:** per-zone selection in `DeclareAttackersMode8()` (runs after mobility so
  zones are known). For each zone row with `attack_type` 1–4, `attack_pct%` of the
  vehicles *in that zone* are marked (same hash ranking, per zone). `attack_type 5`
  marks the RSUs in that zone malicious; `attack_type 6` marks the controller malicious;
  `attack_type 0` = clean zone. **`sybil_attack_percentage` is ignored for vehicle
  selection in mode 8.**

### 5.2 Fanout is clamped, then hard-capped per type

`--sybilFanoutRange`/`--sybilIdsPerAttacker` sets a per-attacker "fanout" that is:
1. clamped to `[1,20]` at parse time, then
2. **hard-capped again per attack type** when beacons are scheduled.

The drawn value is what appears in the `sybil_fanout` CSV column, but the number of
phantom identities actually emitted is the smaller of the two:

| Attack type | Effective phantom cap | Constant / function |
|---|---|---|
| 1 Outsider | `min(fanout, 4)` | `N_SYBIL_OUTSIDER_NEIGHBORS_MAX = 4` |
| 2 Simultaneous | `min(fanout, 4)` | `N_SYBIL_SIMULTANEOUS_MAX = 4` |
| 3 Non-Simultaneous | `min(fanout, 5)` identities/cycle | `N_SYBIL_NON_SIMULTANEOUS_MAX = 5` |
| 4 Indirect (relay) | **fanout not used** | relay forwarding; count is topology-driven |
| 5 Malicious RSU | `RsuSybilBudget()` = `{2,3,4,5}[level−1]` (default **3**) | driven by `--sybil_attacker_level`, **not** fanout |
| 6 Malicious Controller | `SdnSybilBudget()` = `{1,3,3,4}[level−1]` (default **3**) | driven by `--sybil_attacker_level`, **not** fanout |

**Practical consequences:**
- Setting `--sybilFanoutRange=2,20` mostly just varies the *logged* `sybil_fanout`
  value; the actual beacons for types 1–3 never exceed 4–5. Use `2,5` if you want the
  logged value to match reality, or keep a wider range only if you want fanout as a
  noisy input feature.
- To change type-5/6 phantom volume, change `--sybil_attacker_level` (1–4), not fanout.
- `--seed` makes both the attacker set and the fanout draws reproducible.

---

## 6. The `simTime` gotcha (applies to both modes)

Order of operations in `main()`:
1. `AutoConfigureSumoMode()` runs first. If `simTime <= 12.0` it is **overwritten** by
   the SUMO trace length (~119 s for the KL trace).
2. *Then* mode 9 multiplies by 6 (`g_seq6PhaseDuration = simTime; simTime *= 6`).

So:

- **Any `--simTime <= 12` is NOT honored** — it silently becomes the full trace length.
- **Mode 9:** `--simTime` is the **per-phase** length and must be **> 12**.
  Total run = `6 × simTime`. Example: `--simTime=60` → 360 s total, ~60 s/phase.
  Shortest real smoke: `--simTime=13` → 78 s total.
- **Mode 8:** `--simTime` is the **total** length and must be **> 12** to be honored
  (e.g. `--simTime=120`). Otherwise it defaults to the trace length.

**Confirm it was honored** — the console prints one of:
```
[Mobility] sumoAutoConfig: simTime kept at user value 60 s (trace has ... s)   ✅ honored
[Mobility] sumoAutoConfig: simTime 10 -> 119 (from trace ...)                   ❌ overridden
[sybil_attacks] Sequential-all-6 mode: 6 phases x 60s = 360s total run.         (mode 9 only)
```

### Mode 9 phase timing

Phase `p` (0-indexed, `D = per-phase simTime`, onset `2 s`, end gap `3 s`):

```
start = max(p*D, 2.0)
end   = (p+1)*D − 3.0
```

With `D=13`: phase0 `[2,10]`, phase1 `[13,23]`, … phase5 `[65,75]`, sim ends at 78 s.
This exact table is also written to `attack_phases_seq6.csv`.

---

## 7. Mode 8 — Zone-Concurrent in depth

### 7.1 Zones = controllers

A vehicle's zone is the controller that owns its nearest RSU (`ZoneOfPosition` →
`g_rsuControllerAssignment`), frozen at spawn (`InitVehicleHomeZones`). RSUs are split
across controllers by index:
`controllerIndex = min(N_Controllers−1, rsuIndex*N_Controllers / N_RSUs)`.

**`N_Controllers` is NOT auto-derived from the trace — it defaults to `1`.** The three
shipped profiles define **4 zones** (`zone_id` 0–3), so you must pass **`--N_Controllers=4`**
or every vehicle collapses into zone 0 and only the `zone_id=0` row of the CSV takes
effect (no error, just wrong data). Requires `N_RSUs ≥ 4` (the KL trace has 6).

> ⚠️ The bundled `dataset_sweep_v2.sh` does **not** set `--N_Controllers`, so as written
> its mode-8 runs collapse to a single zone. Add `--N_Controllers=4` to `run_mode2()`
> if you want true multi-zone data.

### 7.2 zone_profiles CSV format

Header: `zone_id,attack_type,attack_pct[,fanout_min,fanout_max]`
(`fanout_min`/`fanout_max` optional; fall back to `--sybilFanoutRange`).

```
zone_id      controller/zone index (0..N_Controllers-1)
attack_type  0=clean, 1..6 = attack variant for that zone
attack_pct   % of that zone's vehicles that attack (types 1-4 only)
fanout_min   per-attacker fanout lower bound (optional)
fanout_max   per-attacker fanout upper bound (optional)
```

Shipped profiles in `sybil-attack/inputs/`:

| File | Zone 0 | Zone 1 | Zone 2 | Zone 3 |
|---|---|---|---|---|
| `zone_profiles_default.csv` | type 3 @50% | type 2 @50% | clean | type 4 @50% |
| `zone_profiles_ctrl.csv` | type 3 @50% | type 2 @50% | type 5 (RSU) @100% | type 6 (ctrl) @100% |
| `zone_profiles_heavy.csv` | type 3 @80% (5–20) | type 2 @80% | type 1 @80% | type 4 @80% |

### 7.3 Customizing mode 8

- **Change the attack mix / density:** edit or copy a `zone_profiles_*.csv`. One row per
  zone, pick `attack_type` and `attack_pct`. Point `--zoneProfiles` at your file.
- **More zones:** add rows `zone_id=4,5,…` *and* raise `--N_Controllers` to match.
- **Global fanout:** `--sybilFanoutRange=min,max` or `--sybilIdsPerAttacker=N`
  (per-row `fanout_min/max` in the CSV override these for that zone).
- Mode 8 does **not** use `--intensitySchedule` / `--intensityLadder` (those are mode 9).

---

## 8. Mode 9 — Sequential-All-6 in depth

Six phases, types 1→2→3→4→5→6, each `--simTime` seconds (see §6 timing).

### 8.1 Intensity schedule

- **`fixed`** (default): active attacker % stays at `sybil_attack_percentage` the whole run.
- **`stepped`**: inside *each* phase the active % ramps through `--intensityLadder`
  across `--intensitySubwindows` equal sub-windows, then **resets** at the next phase.
  Example (ladder `20,40,60,80,100`, 5 sub-windows, 13 s phase → ~2.6 s each):
  `20% → 40% → 60% → 80% → 100%`, repeated for every attack type.

Two rules for `stepped`:
1. The ramp is **capped by `sybil_attack_percentage`** (a node only fires if it is also
   in the globally declared attacker set). To let it climb to 100%, set
   `--sybil_attack_percentage=100`.
2. Only **vehicle phases (1–4)** ramp. Phases 5 (RSU) and 6 (controller) are
   control-plane injections and ignore the ladder.

Keep `--intensitySubwindows` equal to the number of ladder entries for a clean 1:1 ramp;
extra sub-windows reuse the last ladder value.

The live value is recorded per row in the `active_attack_pct` column.

### 8.2 Customizing mode 9

- **Longer/shorter phases:** `--simTime` (per phase, `>12`).
- **More/fewer attackers:** `--sybil_attack_percentage`.
- **Type-5/6 volume:** `--sybil_attacker_level` (1–4).
- **Ramp shape:** `--intensitySchedule=stepped --intensityLadder=... --intensitySubwindows=...`.
- **Fanout as a feature:** `--sybilFanoutRange` / `--sybilIdsPerAttacker` (remember §5 caps).

---

## 9. Output files

Written under `--outputDir`. Columns below are exact.

**`communication_log.csv`** — main dataset. In any dataset mode it gets **11 extra
columns** appended after the legacy `...,status,attack_type`:

```
run_id, seed, scenario_id, observing_zone, tx_home_zone, observer_obu_id,
observing_rsu_id, is_attacker, attack_type_label, active_attack_pct, sybil_fanout
```

- `attack_type_label` — per-row ground-truth class (mode 9: the active phase type;
  mode 8: the transmitter's zone attack type). **This is your training label.**
- `is_attacker` — 1 if the transmitter's claimed ID ≠ its real ID.
- `active_attack_pct` — live attacker % (constant, or the stepped value in mode 9).
- `sybil_fanout` — the *drawn* fanout of the transmitter (see §5 caps re: effective count).
- `observing_zone` / `tx_home_zone` — receiver zone and transmitter home zone.

**`run_meta.json`** — one per run:
```
mode, seed, run_id, scenario_id, sim_time_per_phase, total_sim_time,
intensity_schedule, fanout_min, fanout_max, sybil_attack_percentage,
N_Vehicles, N_RSUs, N_Controllers
```

**`rsu_approval_log.csv`** (phase-5 / type-5 injections):
```
run_id, sim_time, rsu_id, zone_id, approved_claimed_id, rssi_corroborated, is_malicious_rsu
```

**`controller_log.csv`** (phase-6 / type-6 injections):
```
run_id, sim_time, controller_id, zone_id, fraudulent_registrations, model_param_norm, is_malicious_ctrl
```

**Mode 9 only:**
- `attack_phases_seq6.csv` — `phase, attack_type, start_time, end_time`
- `sybil_attackers_seq6.csv` — `attacker_node_id`

**Mode 8 only:**
- `sybil_attackers_mode8.csv` — `attacker_node_id, attack_type, zone_id, fanout`

> `sybil-developing-netanim.xml` (NetAnim) is intentionally **not** redirected to
> `--outputDir` — it stays in `sybil-attack/outputs/`.

---

## 10. Command recipes

All from the ns-3.35 root, after `./waf build`.

**Mode 9 — smoke (shortest honored run, ~78 s sim):**
```bash
mkdir -p sybil-attack/outputs/smoke_seq6
./waf --run "Sybil-Developing-Improved \
  --mobility_mode=5 --sumoAutoConfig=true --routing_test=false \
  --sybil_attack_enabled=true --datasetMode=sequential_all6 \
  --sybil_attack_percentage=50 --sybilFanoutRange=2,5 \
  --simTime=13 --beaconInterval=0.1 \
  --seed=1 --runId=smoke_seq6_s1 --scenarioId=smoke \
  --outputDir=sybil-attack/outputs/smoke_seq6"
```

**Mode 9 — stepped intensity, full ramp to 100%:**
```bash
mkdir -p sybil-attack/outputs/seq6_stepped
./waf --run "Sybil-Developing-Improved \
  --mobility_mode=5 --sumoAutoConfig=true --routing_test=false \
  --sybil_attack_enabled=true --datasetMode=sequential_all6 \
  --sybil_attack_percentage=100 --sybilFanoutRange=2,5 \
  --intensitySchedule=stepped --intensityLadder=20,40,60,80,100 --intensitySubwindows=5 \
  --simTime=60 --beaconInterval=0.1 \
  --seed=1 --runId=seq6_stepped_s1 --scenarioId=seq6_stepped \
  --outputDir=sybil-attack/outputs/seq6_stepped"
```

**Mode 8 — each shipped profile (note `--N_Controllers=4`):**
```bash
for P in default ctrl heavy; do
  mkdir -p sybil-attack/outputs/zone_${P}
  ./waf --run "Sybil-Developing-Improved \
    --mobility_mode=5 --sumoAutoConfig=true --routing_test=false --N_Controllers=4 \
    --sybil_attack_enabled=true --datasetMode=zone_concurrent \
    --zoneProfiles=sybil-attack/inputs/zone_profiles_${P}.csv \
    --sybilFanoutRange=2,5 \
    --simTime=120 --beaconInterval=0.1 \
    --seed=1 --runId=zone_${P}_s1 --scenarioId=zone_${P} \
    --outputDir=sybil-attack/outputs/zone_${P}"
done
```

**Full sweep (both modes, many seeds/profiles, merge + class distribution):**
```bash
bash sybil-attack/commands/dataset_sweep_v2.sh
# with overrides:
SIM_TIME=120 N_PARALLEL=4 SEEDS_M1="1 2 3" SEEDS_M2="1 2 3" \
  FANOUT_RANGE="2,5" INTENSITY=stepped \
  bash sybil-attack/commands/dataset_sweep_v2.sh
```
Sweep env vars: `SIM_TIME, N_PARALLEL, STAGGER_SEC, MEM_CAP_GB, SEEDS_M1, SEEDS_M2,
ZONE_PROFILES, ATK_PCT, FANOUT_RANGE, INTENSITY, MOBILITY_MODE`. Outputs land in
`sybil-attack/datasets/dataset_v2_<timestamp>/` with `merged_communication_log.csv` and
`class_distribution.csv`. (Add `--N_Controllers=4` to `run_mode2()` first — see §7.1.)

---

## 11. Post-run verification checklist

```bash
cd <outputDir>
ls -la                              # comm log, run_meta.json, per-mode CSVs present
cat run_meta.json                   # mode, total_sim_time, N_Controllers correct
head -1 communication_log.csv       # 11 dataset columns appended
# class balance:
awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i=="attack_type_label") c=i; next}
         c{n[$c]++} END{for(k in n) print "label="k, n[k]}' communication_log.csv | sort
wc -l rsu_approval_log.csv controller_log.csv   # >1 line each = type 5/6 fired
# mode 9 only:
cat attack_phases_seq6.csv          # 6 phases, types 1..6, sane start/end
# mode 8 only:
cut -d, -f3 sybil_attackers_mode8.csv | sort | uniq -c   # attackers spread across zones
```

Expected: mode 9 shows labels 1–6 over time (0 = pre-onset/benign rows); mode 8 shows
attackers in multiple zones with per-zone types matching your profile. No
`error/assert/abort/bad_alloc` in the run log.

Use this (survives disconnect)

cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35
mkdir -p sybil-attack/datasets/seq6_full_s1
nohup bash -c './waf --run "Sybil-Developing-Improved \
  --mobility_mode=5 --sumoAutoConfig=true --routing_test=false --SecEnabled=false \
  --sybil_attack_enabled=true --datasetMode=sequential_all6 \
  --sybil_attack_percentage=60 \
  --intensitySchedule=stepped --intensityLadder=0,20,40,60 --intensitySubwindows=4 \
  --sybilFanoutRange=2,5 \
  --simTime=60 --beaconInterval=0.1 \
  --seed=1 --runId=seq6_full_s1 --scenarioId=seq6_full \
  --outputDir=sybil-attack/datasets/seq6_full_s1" \
  && touch sybil-attack/datasets/seq6_full_s1/_DONE' \
  > sybil-attack/datasets/seq6_full_s1/run.log 2>&1 &
echo "PID $!"
Then confirm it started, and you can safely close SSH:


sleep 90; tail -20 sybil-attack/datasets/seq6_full_s1/run.log   # look for "6 phases x 60s = 360s"
When you reconnect later
Your shell is gone, but the process and its log persist. Check on it with:


cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35
pgrep -af "build/scratch/Sybil-Developing-Improved" || echo "finished"
ls sybil-attack/datasets/seq6_full_s1/_DONE 2>/dev/null && echo "DONE"   # marker appears only on success
tail -20 sybil-attack/datasets/seq6_full_s1/run.log
Two small notes:

nohup survives an SSH drop, but not a machine reboot — if the server restarts, the run is gone.
echo "PID $!" prints the bash -c wrapper's PID; to check/kill the actual sim reliably use the pgrep/pkill -f "build/scratch/Sybil-Developing-Improved" form.
tmux is the other good option (run it "directly," detach, reconnect and reattach with tmux attach -t seq6) — but for a fire-and-forget 11 h job, nohup … & is simplest.
# S-SOTA-3 — Network Scalability (mobility modes 10–13)

Population sweep derived from mode 5's klbb2km scenario. **Mode 5 and every file in
the parent directory are read-only inputs here and were not modified.**

Regenerate with:

```bash
cd sybil-attack/inputs/mobility/kuala-lumpur-bb/sota3_scale
python3 build_sota3_scale.py --fcd-dir /some/scratch/dir
```

## Run matrix

| mode | N_V | RSUs = ⌊64·N_V/200⌋ | grid | trace | RSU CSV |
|---|---|---|---|---|---|
| 10 | 100 | 32 | 8×4 | `klbb2km_n100_mobility.tcl` | `klbb2km_rsus_8x4.csv` |
| 11 | 200 | 64 | 8×8 | `klbb2km_n200_mobility.tcl` | `../klbb2km_rsus_8x8.csv` |
| 12 | 300 | 96 | 12×8 | `klbb2km_n300_mobility.tcl` | `klbb2km_rsus_12x8.csv` |
| 13 | 400 | 128 | 16×8 | `klbb2km_n400_mobility.tcl` | `klbb2km_rsus_16x8.csv` |

```bash
./waf --run "Sybil-Developing-Improved --mobility_mode=13 --routing_test=false \
    --simTime=300 --sybil_attack_percentage=40 --sybilIdentitiesPerAttacker=3"
```

`--routing_test=false` is **mandatory** (see the S-SOTA-2 README). With it off,
`N_Vehicles` and `N_RSUs` are read from the files automatically. Attacker
proportion stays 40 % of N_V, so the absolute attacker count scales with the level.

## What varies, and what does not

Only the vehicle population. The road net, the vTypes, the 60 rerouter hubs and the
50/10/10/10/10/10 % class mix are all mode 5's, unchanged.

Route sets are **strictly nested**, 100 ⊂ 200 ⊂ 300 ⊂ 400:

- level 200 is mode 5's exact 200 vehicles — `../klbb2km.rou.xml` is read verbatim
  and `klbb2km_n200.rou.xml` is byte-identical to it in ids, types and edges.
- levels 300 and 400 keep those 200 at their original ids `0..199` and append fresh
  routes (seed 43) as ids `200+`, so node *i* is the same vehicle at N=200/300/400.
- level 100 is a per-class subset of mode 5's own 200, taken in original id order and
  recompacted to contiguous ids `0..99` (the ns-2 format requires contiguous ids, so
  a subset cannot keep them).

Levels ≤ 200 reuse mode 5's keepalive rerouter verbatim. Levels 300/400 use
`klbb2km_keepalive_n400.add.xml`, which keeps mode 5's **60 destination hubs
unchanged** and only widens the trigger-edge set (3074 → 3157) so the added
vehicles get re-destined instead of driving off the map. Changing the hub count
would change the mobility character, so it is not done.

## ⚠ Why mode 11 does not point at `klbb2km_mobility.tcl`

The committed mode-5 trace carries **259 contiguous ns-2 node ids** even though
`klbb2km.rou.xml` defines 200 vehicles and `klbb2km_fcd.xml` contains exactly 200
distinct vehicle ids. The 59 extra nodes are an artefact of the older traceExporter
that produced that file; re-exporting the same routes with SUMO 1.27 yields exactly
200. Pointing the anchor at it would make `sumoAutoConfig` read `N_Vehicles=259` and
turn this sweep's x-axis into 100/**259**/300/400.

So the anchor is regenerated here. **Mode 5 itself is untouched and still resolves to
the 259-node trace, so no existing baseline run changes behaviour** — but note that
every mode-5 result in the thesis was produced on a 259-vehicle topology, not 200.

## ⚠ Two confounds to report with the results

**RSU density.** RSU count is tied to N_V by the spec, so inter-RSU spacing shrinks
as the network grows. Registration coverage therefore improves partly *because RSUs
get closer*, not only because the system scales — which matters given that Cost231
caps effective radio range near 100 m.

| N_V | dx | dy | median vehicle→nearest-RSU at spawn |
|---|---|---|---|
| 100 | 306.85 m | 653.07 m | 218 m |
| 200 | 306.85 m | 326.53 m | 134 m |
| 300 | 204.57 m | 326.53 m | 106 m |
| 400 | 153.42 m | 326.53 m | 98 m |

At N_V=100 the median vehicle spawns 218 m from its nearest RSU, so expect Ĉ_R to be
poor there for reasons unrelated to scale.

**Congestion.** Achieved mean speed falls as the population grows — 9.12 / 7.34 /
6.17 / 5.60 m/s at N_V = 100/200/300/400. Scale and speed are therefore coupled in
this sweep; S-SOTA-2 varies speed at fixed N_V=200 if you need them separated.

## Validation (all four levels)

Node count exactly N_V, RSU CSV row count exactly as tabulated, trace ends at
299.9 s, 0 teleports, ≥96 % of vehicles concurrently present in the steady-state
window (t ≥ 100 s). The 8×8 grid convention is asserted against the committed
`../klbb2km_rsus_8x8.csv` at build time, so all four grids share one convention.

The large FCD files are intermediates and are deliberately not kept here.

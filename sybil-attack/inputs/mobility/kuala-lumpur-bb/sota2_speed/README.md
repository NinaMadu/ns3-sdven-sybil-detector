# S-SOTA-2 — Vehicle Mobility (mobility modes 6–9)

Speed sweep derived from mode 5's klbb2km scenario. **Mode 5 and every file in the
parent directory are read-only inputs here and were not modified.**

Regenerate with:

```bash
cd sybil-attack/inputs/mobility/kuala-lumpur-bb/sota2_speed
python3 build_sota2_speed.py --fcd-dir /some/scratch/dir
```

## Run matrix

| mode | nominal v | m/s | trace | RSU CSV |
|---|---|---|---|---|
| 6 | 10 km/h | 2.78 | `klbb2km_v010_mobility.tcl` | `../klbb2km_rsus_8x8.csv` |
| 7 | 40 km/h | 11.11 | `klbb2km_v040_mobility.tcl` | `../klbb2km_rsus_8x8.csv` |
| 8 | 60 km/h | 16.67 | `klbb2km_v060_mobility.tcl` | `../klbb2km_rsus_8x8.csv` |
| 9 | 100 km/h | 27.78 | `klbb2km_v100_mobility.tcl` | `../klbb2km_rsus_8x8.csv` |

```bash
./waf --run "Sybil-Developing-Improved --mobility_mode=8 --routing_test=false \
    --simTime=300 --sybil_attack_percentage=40 --sybilIdentitiesPerAttacker=3"
```

`--routing_test=false` is **mandatory** — it defaults to true and silently forces a
3-vehicle/2-RSU topology, skipping `sumoAutoConfig` entirely. With it off,
`N_Vehicles=200` and `N_RSUs=64` are read from the files automatically.

## What varies, and what does not

Only the road speed limit and the vType caps change. Reused byte-for-byte from
mode 5: the 200 routes (`../klbb2km.rou.xml`), the keepalive rerouter, and the
64-RSU 8×8 deployment. Per point, the net is re-emitted with
`netconvert --speed.factor 0 --speed.offset <v>` (all 4096 lanes forced to exactly
`v`, all 3879 edge ids preserved) and the six vTypes get
`maxSpeed=v speedFactor="1" speedDev="0"`.

The only deviation from mode 5's route file is `departSpeed="0"` → `"max"`, so a
bus (accel 1.2 m/s²) does not spend ~30 s of a 300 s run spinning up.

Note the v=60 km/h point is **not** mode 5: mode 5 has heterogeneous road speeds
(16.67/22.22/27.78) and heterogeneous vType caps, and sets no `speedFactor`, so it
inherits SUMO's `normc(1,0.1,0.2,2)` speed dispersion.

## ⚠ Achieved speed saturates — report it alongside the nominal x-axis

| nominal | 10 | 40 | 60 | 100 km/h |
|---|---|---|---|---|
| achieved mean | 2.55 | 7.10 | 7.34 | 8.01 m/s |
| % of nominal | 91.7 | 63.9 | 44.1 | 28.8 |

klbb2km's median edge is **39.5 m** (mean 54.6, p90 114.7). A car at 2.6 m/s²
crossing a whole median edge without braking tops out at 14.3 m/s, a bus at
9.7 m/s — then it must decelerate for the next junction. Above ~40 km/h the posted
limit stops being the binding constraint and edge geometry takes over, so 40/60/100
are compressed into 7.1–8.0 m/s. Only the 10 km/h point separates cleanly.

This is why the sweep is 10/40/60/100 and not the originally drafted 10/60/100/140:
at 140 km/h the achieved mean was 7.78 m/s, i.e. indistinguishable from 60. Three
candidate causes were measured and all came back null:

- junction turn-speed limits (`--junctions.limit-turn-speed -1`): 7.78 → 7.78
- traffic lights (only 13 of ~1500 junctions are signalised): no change
- rerouter hub funnelling (60 → 1855 destination hubs): 7.78 → 7.44

Treat the x-axis as the nominal speed limit and publish the achieved column with it.

## Validation (all four points)

200 ns-2 nodes, trace ends at 299.9 s, 0 teleports, ≥191 of 200 vehicles
concurrently present in the steady-state window (t ≥ 100 s), 95 % population
reached by t ≈ 21–24 s. Mode 5's own baseline dips to 195/200, so this is normal
for the recipe.

The large FCD files are intermediates and are deliberately not kept here; pass
`--fcd-dir` to put them somewhere scratch.

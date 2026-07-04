# NS-3 SDVEN Sybil Attack Simulation

This branch is the clean attack-implementation base for the ns-3.35 SDVEN
Sybil simulation.

The repository should track only the simulation source, scenario configs,
security/input generators, and input data needed to reproduce runs. Generated
outputs and result artifacts must stay untracked.

## Requirement

This repository is the project overlay for an existing ns-3.35 installation; it
does not track the full ns-3 source tree. Each team member should place these
files in the ns-3.35 root where `./waf` is available, for example:

```text
ns-allinone-3.35/ns-3.35/
  scratch/
  sybil-attack/
  waf
```

## Project Layout

```text
scratch/
  Sybil-Developing-Improved.cc   Main ns-3 simulation entry point
  sybil_attacks.h                Sybil attack scenarios and scheduling
  sybil_crypto.h                 Security helpers
  sybil_metrics.h                Evaluation metrics and CSV writers
  sybil_types.h                  Shared packet/data structures

sybil-attack/
  configs/                       Scenario configuration files
  inputs/                        Tracked runtime inputs
    *.csv                        Security keys, VINs, token inputs
    mobility/
      colombo-small/             Colombo OSM/SUMO network, routes, FCD, ns-2 trace
      synthetic-urban/           Synthetic SUMO network, routes, FCD, ns-2 trace
  security/                      Python scripts that generate input keys/VINs
  outputs/                       Generated run outputs, ignored by Git
```

## Git Tracking Rules

Track:

- `README.md`
- `.gitignore`
- `scratch/Sybil-Developing-Improved.cc`
- `scratch/sybil_*.h`
- `sybil-attack/configs/**`
- `sybil-attack/inputs/*.csv`
- `sybil-attack/inputs/mobility/**`
- `sybil-attack/security/**`

Do not track:

- `sybil-attack/outputs/**`
- evaluation run folders
- visualizations
- NetAnim XML outputs
- logs, plots, PCAPs, temporary files, and build/cache artifacts

## Build

From the ns-3.35 root:

```bash
./waf build
```

## Run

Quick smoke test:

```bash
./waf --run "Sybil-Developing-Improved --config=sybil-attack/configs/quick_test.cfg"
```

No-detection attack baseline:

```bash
./waf --run "Sybil-Developing-Improved --config=sybil-attack/configs/no_detection.cfg"
```

Baseline1 FL placeholder scenario:

```bash
./waf --run "Sybil-Developing-Improved --config=sybil-attack/configs/sybil_fl_detection.cfg"
```

Manual command example:

```bash
./waf --run "Sybil-Developing-Improved --routing_test=false --N_Vehicles=10 --N_RSUs=2 --simTime=60 --sybil_attack_enabled=true --sybil_attack_type=2 --sybil_attack_percentage=40 --solution_mode=4"
```

Solution/detection mode uses `solution_mode`:

```text
1 = Baseline1 FL Detection placeholder
2 = Baseline2 RSSI Detection placeholder
3 = Baseline3 ML Detection placeholder
4 = Lightweight Mode
5 = Full Mode placeholder
6 = No Detection
```

Only modes 4 and 6 are implemented at this stage. Placeholder modes are
selectable and labelled in metrics, but they intentionally keep detection logic
disabled so their behavior is not mixed with the lightweight solution.

Mobility mode is selected with `mobility_mode`:

```text
1 = test network constant-velocity mobility
2 = programmed bounded-road mobility
3 = SUMO synthetic urban trace
4 = SUMO Colombo-small trace
5 = reserved third SUMO/ns-2 trace placeholder
```

Examples:

```bash
./waf --run "Sybil-Developing-Improved --config=sybil-attack/configs/baseline.cfg --mobility_mode=2"
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=3 --N_Vehicles=12 --N_RSUs=3 --simTime=12"
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=4 --N_Vehicles=10 --N_RSUs=5 --simTime=60"
./waf --run "Sybil-Developing-Improved --mobility_mode=5 --mobilityMode5TraceFile=sybil-attack/inputs/mobility/<scenario>/<trace>.tcl"
```

Mode 2 is the current controlled baseline mobility: vehicles move along a
bounded multi-lane road with configurable road length, lanes, spacing, and
speed range. Modes 3-5 replay SUMO-generated ns-2 mobility traces through
ns-3's `Ns2MobilityHelper`; mode 4 also loads Colombo RSU positions from
`colombo_small_rsus_300m.csv` by default. Mode 5 is intentionally a placeholder
until the third SUMO scenario is generated.

Each SUMO mode has independent config keys so scenarios can be maintained
without changing the C++ logic:

```text
mobilityMode3Name
mobilityMode3TraceFile
mobilityMode3RsuPositionFile

mobilityMode4Name
mobilityMode4TraceFile
mobilityMode4RsuPositionFile

mobilityMode5Name
mobilityMode5TraceFile
mobilityMode5RsuPositionFile
```

For one-off experiments, `mobilityTraceFile` and `mobilityRsuPositionFile` can
override the selected SUMO mode without editing the scenario defaults.

## Inputs

Runtime inputs live in `sybil-attack/inputs/` and should be committed when they
are needed to reproduce a simulation.

The security/key inputs currently stay directly under `sybil-attack/inputs/`
because the C++ simulation loads those exact paths:

```text
sybil-attack/inputs/vehicle_keys.csv
sybil-attack/inputs/rsu_keys.csv
sybil-attack/inputs/ca_keys.csv
sybil-attack/inputs/controller_keys.csv
sybil-attack/inputs/vehicle_vins.csv
sybil-attack/inputs/valid_vins.csv
sybil-attack/inputs/token_master_key.csv
```

Mobility and SUMO inputs are grouped by scenario:

```text
sybil-attack/inputs/mobility/<scenario-name>/
  <scenario>.net.xml              SUMO network
  <scenario>.rou.xml              route definitions
  <scenario>_fcd.xml              SUMO floating-car trace
  <scenario>_mobility.tcl         ns-2 mobility trace for ns-3
  <scenario>_rsus.csv             optional RSU placement input

sybil-attack/inputs/mobility/colombo-small/
  colombo_small_bbox.osm.xml      OSM extract used to build the network
  colombo_small.netccfg           SUMO netconvert config
  colombo_small.net.xml           SUMO network
  colombo_small.trips.xml         Trip definitions
  colombo_small.rou.xml           Route definitions
  colombo_small.rou.alt.xml       Alternate route output
  colombo_small_fcd.xml           SUMO floating-car trace
  colombo_small_mobility.tcl      ns-2 mobility trace for ns-3
  colombo_small_rsus_300m.csv     RSU placement input

sybil-attack/inputs/mobility/synthetic-urban/
  urban_arterial.nod.xml          SUMO nodes
  urban_arterial.edg.xml          SUMO edges
  urban_arterial.net.xml          SUMO network
  urban_arterial.rou.xml          Route definitions
  urban_arterial.sumocfg          SUMO run config
  sumo_fcd.xml                    SUMO floating-car trace
  sumo_mobility.tcl               ns-2 mobility trace for ns-3
```

The simulation can generate missing key/VIN inputs through:

```bash
python3 sybil-attack/security/generate_ca_rsu_keys.py --rsus 2 --out-dir sybil-attack/inputs
python3 sybil-attack/security/generate_vehicle_keys.py --vehicles 10 --out sybil-attack/inputs/vehicle_keys.csv
python3 sybil-attack/security/generate_vehicle_vins.py --vehicles 10 --out-dir sybil-attack/inputs
```

## Outputs

Run outputs are written under `sybil-attack/outputs/`, for example:

```text
sybil-attack/outputs/communication_log.csv
sybil-attack/outputs/metrics_summary.csv
sybil-attack/outputs/sybil-developing-netanim.xml
```

These files are generated artifacts and are intentionally ignored by Git.

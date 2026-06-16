# Mobility And Routing Test Report

## Purpose

This report explains the mobility menu, routing test approach, and sample commands for the Sybil-Developing SDVN/ns-3 simulation.

The simulation now supports selectable mobility modes through `mobility_mode`. The SUMO mobility scenarios are separated so each trace can be updated independently without changing the main simulation logic.

## Mobility Menu

```text
1 = Test network mobility
2 = Programmed bounded-road mobility
3 = SUMO synthetic urban trace
4 = SUMO Colombo-small trace
5 = Reserved third SUMO/ns-2 trace placeholder
```

## Mobility Mode Details

### Mode 1: Test Network Mobility

Small constant-velocity mobility for quick validation.

Recommended use:

```text
Quick smoke tests and basic routing checks.
```

### Mode 2: Programmed Bounded-Road Mobility

Vehicles are generated inside ns-3 on a configurable bounded road. This is useful as a controlled baseline.

Recommended use:

```text
Baseline experiments where vehicle placement and movement should be predictable.
```

### Mode 3: SUMO Synthetic Urban Trace

Uses the synthetic SUMO/ns-2 trace:

```text
sybil-attack/inputs/mobility/synthetic-urban/sumo_mobility.tcl
```

Current trace size:

```text
Vehicles: 3
Trace duration: about 11.5 seconds
```

### Mode 4: SUMO Colombo-Small Trace

Uses the Colombo SUMO/ns-2 trace:

```text
sybil-attack/inputs/mobility/colombo-small/colombo_small_mobility.tcl
```

Uses RSU positions from:

```text
sybil-attack/inputs/mobility/colombo-small/colombo_small_rsus_300m.csv
```

Current trace size:

```text
Vehicles: 27
Trace duration: about 59 seconds
RSU positions: 23
```

### Mode 5: Third SUMO Trace Placeholder

Mode 5 is available in the menu but intentionally has no default trace yet.

Expected behavior:

```text
The simulation stops with a clear message asking for mobilityMode5TraceFile or mobilityTraceFile.
```

## Test Menu

There are two recommended test types.

### 1. Smoke Routing Test

Purpose:

```text
Confirm that the simulation runs, packets flow, and the selected mobility backend does not crash.
```

Configuration:

```text
routing_test=true
```

Behavior:

```text
Forces N_Vehicles = 3
Forces N_RSUs = 2
Caps simTime at 12 seconds
```

Recommended use:

```text
Use mainly for mode 1 and quick validation of modes 2-4.
Do not use this as final research evidence for SUMO mobility scenarios.
```

### 2. Mobility-Specific Routing Test

Purpose:

```text
Evaluate routing under realistic settings for each mobility scenario.
```

Configuration:

```text
routing_test=false
```

Recommended use:

```text
Use scenario-matched N_Vehicles, N_RSUs, and simTime.
This is the fair approach for research comparisons.
```

## Build Command

Run from the ns-3 repository root:

```bash
cd /root/FYP/ns-allinone-3.35/ns-3.35
./waf build
```

## Smoke Test Commands

### Mode 1 Smoke Test

```bash
./waf --run "Sybil-Developing-Improved --routing_test=true --mobility_mode=1 --simTime=5 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 2 Smoke Test

```bash
./waf --run "Sybil-Developing-Improved --routing_test=true --mobility_mode=2 --simTime=8 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 3 Smoke Test

```bash
./waf --run "Sybil-Developing-Improved --routing_test=true --mobility_mode=3 --simTime=8 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 4 Smoke Test

```bash
./waf --run "Sybil-Developing-Improved --routing_test=true --mobility_mode=4 --simTime=8 --sybil_attack_enabled=false --proposed_method=0"
```

## Mobility-Specific Research Test Commands

### Mode 2: Programmed Road

```bash
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=2 --N_Vehicles=10 --N_RSUs=3 --simTime=30 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 3: SUMO Synthetic Urban

```bash
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=3 --N_Vehicles=3 --N_RSUs=2 --simTime=11 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 4: SUMO Colombo-Small

```bash
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=4 --N_Vehicles=27 --N_RSUs=23 --simTime=59 --sybil_attack_enabled=false --proposed_method=0"
```

### Mode 5: Placeholder Check

```bash
./waf --run "Sybil-Developing-Improved --routing_test=false --mobility_mode=5 --N_Vehicles=3 --N_RSUs=2 --simTime=5 --sybil_attack_enabled=false --proposed_method=0"
```

Expected result:

```text
Mode 5 should stop with a clear message until the third SUMO/ns-2 trace is added.
```

## Recommendation

Use `routing_test=true` only for quick smoke testing.

Use `routing_test=false` for fair mobility-aware routing experiments.

For research comparisons, do not compare all mobility modes using the forced 3-vehicle/2-RSU routing test. Instead, run each mobility scenario with its matching vehicle count, RSU count, and simulation duration.

# NS-3 SDVEN Sybil Detector

This repository contains selected project files for an ns-3.35 SDVEN Sybil attack simulation. It does not contain the full ns-3 simulator source tree.

The main simulation files are:

- `scratch/Sybil-Developing.cc`
- `scratch/Sybil-Developing-Improved.cc`
- `sybil-attack/`

## What The Simulation Does

The improved simulation creates a small SDVEN-style network:

```text
Vehicles <-> RSUs <-> SDN Controller
```

It sends tagged UDP packets for:

- vehicle-to-vehicle beacons
- vehicle-to-RSU reports
- RSU-to-controller reports
- controller-to-RSU commands
- RSU-to-vehicle commands

The simulation writes communication logs and NetAnim output under `sybil-attack/outputs/`.

## Requirements

Each team member must already have ns-3.35 installed and working.

Example ns-3 path:

```bash
~/FYP/ns-allinone-3.35/ns-3.35
```

Build ns-3 first if needed:

```bash
cd ~/FYP/ns-allinone-3.35/ns-3.35
./waf build
```

## Recommended Setup

Do not clone this repo directly into an existing `ns-3.35` folder. Clone it somewhere separate, then copy the project files into ns-3.

```bash
cd ~/FYP
git clone https://github.com/NinaMadu/ns3-sdven-sybil-detector.git
cd ns3-sdven-sybil-detector
```

Copy files into your ns-3.35 folder:

```bash
cp scratch/Sybil-Developing.cc ~/FYP/ns-allinone-3.35/ns-3.35/scratch/
cp scratch/Sybil-Developing-Improved.cc ~/FYP/ns-allinone-3.35/ns-3.35/scratch/
cp -r sybil-attack ~/FYP/ns-allinone-3.35/ns-3.35/
```

Adjust the destination path if your ns-3.35 folder is somewhere else.

## Run The Simulation

From the ns-3.35 root:

```bash
cd ~/FYP/ns-allinone-3.35/ns-3.35
./waf --run "scratch/Sybil-Developing-Improved"
```

Minimal packet movement test:

```bash
./waf --run "scratch/Sybil-Developing-Improved --routing_test=0 --N_Vehicles=2 --N_RSUs=1 --simTime=6"
```

Larger test:

```bash
./waf --run "scratch/Sybil-Developing-Improved --routing_test=0 --N_Vehicles=20 --N_RSUs=4 --simTime=20"
```

## Output Files

The simulation writes outputs such as:

```text
sybil-attack/outputs/communication_log.csv
sybil-attack/outputs/sybil-developing-netanim.xml
```

Open the XML file with NetAnim:

```bash
cd ~/FYP/ns-allinone-3.35/netanim-3.108
./NetAnim
```

Then choose the XML trace file from `ns-3.35/sybil-attack/outputs/`.

## Updating From GitHub

To get the latest project files:

```bash
cd ~/FYP/ns3-sdven-sybil-detector
git pull origin main
```

Then copy the files into ns-3 again:

```bash
cp scratch/Sybil-Developing.cc ~/FYP/ns-allinone-3.35/ns-3.35/scratch/
cp scratch/Sybil-Developing-Improved.cc ~/FYP/ns-allinone-3.35/ns-3.35/scratch/
cp -r sybil-attack ~/FYP/ns-allinone-3.35/ns-3.35/
```

## Committing Changes

After editing files inside ns-3.35, copy the changed project files back into this cloned repo:

```bash
cp ~/FYP/ns-allinone-3.35/ns-3.35/scratch/Sybil-Developing.cc ~/FYP/ns3-sdven-sybil-detector/scratch/
cp ~/FYP/ns-allinone-3.35/ns-3.35/scratch/Sybil-Developing-Improved.cc ~/FYP/ns3-sdven-sybil-detector/scratch/
cp -r ~/FYP/ns-allinone-3.35/ns-3.35/sybil-attack ~/FYP/ns3-sdven-sybil-detector/
```

Check what changed:

```bash
cd ~/FYP/ns3-sdven-sybil-detector
git status
```

Stage only wanted files:

```bash
git add README.md
git add scratch/Sybil-Developing.cc
git add scratch/Sybil-Developing-Improved.cc
git add sybil-attack
```

Commit and push:

```bash
git commit -m "Describe the change"
git push origin main
```

Before starting new work, always pull first:

```bash
git pull origin main
```

## Git Tracking Rules

This repo intentionally tracks only the selected Sybil project files. It should not track the full ns-3.35 source tree, build outputs, temporary files, or Windows `Zone.Identifier` metadata files.

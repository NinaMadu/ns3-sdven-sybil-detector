#!/usr/bin/env python3
"""Builds the S-SOTA-2 vehicle-mobility sweep: mobility modes 6/7/8/9.

Derived from ../build_klbb2km_traffic.py (mode 5).  Speed is the ONLY variable:

  * the road net is re-emitted from klbb2km.net.xml with every edge forced to
    the exact target speed (netconvert --speed.factor 0 --speed.offset v), which
    removes mode 5's 16.67/22.22/27.78 m/s tiering.  Edge ids are preserved by a
    plain net->net re-import, so mode 5's routes stay valid verbatim.
  * the six vTypes keep their vClass/length/accel/decel/sigma but get
    maxSpeed=v, speedFactor="1", speedDev="0".  Mode 5 sets neither factor nor
    dev, so it inherits SUMO's normc(1,0.1,0.2,2) dispersion -- that is why the
    v=60 km/h point is NOT mode 5 and has to be generated here too.
  * the 200 routes and the keepalive rerouter are reused byte-for-byte from
    mode 5.  Only departSpeed is rewritten 0 -> "max", because at 38.89 m/s a
    bus (accel 1.2) would otherwise spend ~32 s of a 300 s run spinning up.

NOTHING in the parent directory is written to.  Mode 5's files are read-only
inputs here.

Junction internal lanes stay turn-radius limited (netconvert default) and the
traffic lights are untouched, so the ACHIEVED speed will be below the nominal
limit -- especially at 100/140 km/h on a 2 km urban grid.  The validation block
at the end reports achieved speed per mode; treat the x-axis as the nominal
limit and publish the achieved column with it.

Usage:  python3 build_sota2_speed.py [--fcd-dir DIR] [--only 10,60]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                      # kuala-lumpur-bb/ (mode 5, read-only)
SUMO_HOME = os.environ.get("SUMO_HOME", "/usr/share/sumo")
TRACE_EXPORTER = os.path.join(SUMO_HOME, "tools", "traceExporter.py")

SRC_NET = os.path.join(BASE, "klbb2km.net.xml")
SRC_ROU = os.path.join(BASE, "klbb2km.rou.xml")
SRC_VTYPES = os.path.join(BASE, "klbb2km_vtypes.add.xml")
SRC_KEEPALIVE = os.path.join(BASE, "klbb2km_keepalive.add.xml")

SIM_END = 300.0
STEP = 0.1
N_VEHICLES = 200

# (km/h, m/s, mobility_mode).
#
# Speed points are 10/40/60/100 km/h, NOT the 10/60/100/140 originally drafted.
# Measured reason: klbb2km's median edge is 39.5 m (mean 54.6, p90 114.7).  A car
# at accel=2.6 m/s^2 crossing a whole median edge without braking tops out at
# 14.3 m/s, a bus at 9.7 m/s -- and it must then decelerate for the next
# junction.  Above ~60 km/h the posted limit stops being the binding constraint
# and edge geometry takes over, so 140 km/h is indistinguishable from 60:
# achieved mean was 7.41 m/s at 60, 8.06 at 100, 7.78 at 140.
#
# Ruled out as causes before rescaling the sweep (all measured, all null):
#   * junction turn-speed limits (--junctions.limit-turn-speed -1): 7.78 -> 7.78
#   * traffic lights (only 13 of ~1500 junctions are signalised): no change
#   * rerouter hub funnelling (60 -> 1855 destination hubs): 7.78 -> 7.44
POINTS = [(10, 2.78, 6), (40, 11.11, 7), (60, 16.67, 8), (100, 27.78, 9)]

ROU = os.path.join(HERE, "klbb2km_sota2.rou.xml")


def tag(kmh):
    return f"v{kmh:03d}"


def build_routes():
    """Mode 5's routes with departSpeed 0 -> max.  Written once, shared by all 4."""
    with open(SRC_ROU) as f:
        text = f.read()
    out = text.replace('departSpeed="0"', 'departSpeed="max"')
    n = text.count('departSpeed="0"')
    if n != N_VEHICLES:
        sys.exit(f"[routes] expected {N_VEHICLES} departSpeed=\"0\", found {n}")
    with open(ROU, "w") as f:
        f.write(out)
    print(f"[routes] {ROU}: {n} vehicles, departSpeed -> max")


def build_net(kmh, ms):
    dst = os.path.join(HERE, f"klbb2km_{tag(kmh)}.net.xml")
    cmd = ["netconvert", "-s", SRC_NET,
           "--speed.factor", "0", "--speed.offset", f"{ms}",
           "-o", dst, "--no-warnings", "true"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(dst):
        print(r.stderr[-2000:])
        sys.exit(f"netconvert failed for {kmh} km/h")
    # verify: every non-internal lane sits at exactly ms, and no edge was lost
    root = ET.parse(dst).getroot()
    speeds, ids = Counter(), set()
    for e in root.findall("edge"):
        if e.get("function") == "internal":
            continue
        ids.add(e.get("id"))
        for l in e.findall("lane"):
            speeds[round(float(l.get("speed")), 2)] += 1
    src_ids = {e.get("id") for e in ET.parse(SRC_NET).getroot().findall("edge")
               if e.get("function") != "internal"}
    if set(speeds) != {round(ms, 2)}:
        sys.exit(f"[net {kmh}] lane speeds not uniform: {sorted(speeds)}")
    if ids != src_ids:
        sys.exit(f"[net {kmh}] edge id set changed ({len(src_ids - ids)} missing)")
    print(f"[net] {os.path.basename(dst)}: {sum(speeds.values())} lanes @ {ms} m/s, "
          f"{len(ids)} edges preserved")
    return dst


def build_vtypes(kmh, ms):
    dst = os.path.join(HERE, f"klbb2km_{tag(kmh)}_vtypes.add.xml")
    with open(SRC_VTYPES) as f:
        text = f.read()
    text = re.sub(r'maxSpeed="[0-9.]+"', f'maxSpeed="{ms:.2f}"', text)
    # append speedFactor/speedDev to every vType (mode 5 sets neither)
    text = re.sub(r'(<vType\b[^>]*?)\s*/>',
                  r'\1 speedFactor="1" speedDev="0"/>', text)
    text = text.replace("<additional>",
                        "<!-- S-SOTA-2: generated by sota2_speed/build_sota2_speed.py. "
                        f"Uniform maxSpeed={ms:.2f} m/s ({kmh} km/h), no speed dispersion. -->\n"
                        "<additional>", 1)
    with open(dst, "w") as f:
        f.write(text)
    root = ET.parse(dst).getroot()
    for vt in root.findall("vType"):
        assert abs(float(vt.get("maxSpeed")) - ms) < 1e-6, vt.get("id")
        assert vt.get("speedFactor") == "1" and vt.get("speedDev") == "0", vt.get("id")
    print(f"[vtypes] {os.path.basename(dst)}: {len(root.findall('vType'))} vTypes "
          f"@ maxSpeed={ms:.2f}, speedFactor=1, speedDev=0")
    return dst


def run_sumo(kmh, ms, net, vtypes, fcd_dir):
    fcd = os.path.join(fcd_dir, f"klbb2km_{tag(kmh)}_fcd.xml")
    tcl = os.path.join(HERE, f"klbb2km_{tag(kmh)}_mobility.tcl")
    print(f"[sumo] {kmh} km/h ...", flush=True)
    r = subprocess.run(
        ["sumo", "-n", net, "-r", ROU,
         "--additional-files", f"{vtypes},{SRC_KEEPALIVE}",
         "--fcd-output", fcd, "--begin", "0", "--end", str(SIM_END),
         "--step-length", str(STEP), "--time-to-teleport", "60",
         "--no-step-log", "true", "--max-depart-delay", "300"],
        capture_output=True, text=True)
    if not os.path.exists(fcd):
        print(r.stdout[-2000:], r.stderr[-2000:])
        sys.exit(f"sumo failed for {kmh} km/h")
    teleports = r.stdout.count("Teleporting")
    subprocess.run([sys.executable, TRACE_EXPORTER, "--fcd-input", fcd,
                    "--ns2mobility-output", tcl], check=True)
    return fcd, tcl, teleports


STEADY_FROM = 100.0   # s; speed stats are measured over the steady-state window only


def validate(kmh, ms, fcd, tcl, teleports):
    """Speed stats are measured over a FIXED window (t >= STEADY_FROM), never over
    a warm-up-derived one: the mode-5 recipe does not reliably reach 200 exactly
    concurrent (the baseline itself peaks at 200 but dips to 195), so keying the
    window off 'first t with >=200 present' silently yields an empty window and a
    0.00 m/s report.  Warm-up is reported separately at both 100% and 95%."""
    present, mean_speed = {}, {}
    for ts in ET.parse(fcd).getroot().findall("timestep"):
        t = round(float(ts.get("time")), 1)
        vs = ts.findall("vehicle")
        present[t] = len(vs)
        if vs:
            mean_speed[t] = sum(float(v.get("speed")) for v in vs) / len(vs)
    warmup = next((t for t in sorted(present) if present[t] >= N_VEHICLES), None)
    warmup95 = next((t for t in sorted(present)
                     if present[t] >= 0.95 * N_VEHICLES), None)
    steady = [t for t in sorted(present) if t >= STEADY_FROM]
    min_steady = min((present[t] for t in steady), default=0)
    mean_present = (sum(present[t] for t in steady) / len(steady)) if steady else 0.0
    ach = sorted(mean_speed[t] for t in steady if t in mean_speed)
    achieved = sum(ach) / len(ach) if ach else 0.0
    median = ach[len(ach) // 2] if ach else 0.0
    tmax = max(present) if present else 0.0

    with open(tcl) as f:
        nodes = len(set(re.findall(r"\$node_\((\d+)\)", f.read())))

    print(f"  [check {kmh:3d} km/h] nominal={ms:5.2f} m/s  achieved mean={achieved:5.2f} "
          f"median={median:5.2f} ({100*achieved/ms:4.1f}% of nominal)")
    print(f"                    warmup(100%)={warmup}s  warmup(95%)={warmup95}s  "
          f"steady min/mean present={min_steady}/{mean_present:.0f} of {N_VEHICLES}  "
          f"peak={max(present.values())}  trace_end={tmax}s  tcl_nodes={nodes}  "
          f"teleports={teleports}")
    if nodes != N_VEHICLES:
        sys.exit(f"[check {kmh}] tcl has {nodes} nodes, expected {N_VEHICLES}")
    if tmax < SIM_END - 1.0:
        sys.exit(f"[check {kmh}] trace ends at {tmax}s, expected ~{SIM_END}s")
    return dict(kmh=kmh, nominal=ms, achieved=achieved, median=median, warmup=warmup,
                warmup95=warmup95, min_steady=min_steady, mean_present=mean_present,
                peak=max(present.values()), tmax=tmax, nodes=nodes, teleports=teleports)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fcd-dir", default=os.environ.get("SOTA2_FCD_DIR", "/tmp"),
                    help="where the (large) FCD files go; they are not repo artefacts")
    ap.add_argument("--only", default="", help="comma-separated km/h subset, e.g. 10,60")
    args = ap.parse_args()
    os.makedirs(args.fcd_dir, exist_ok=True)

    for p in (SRC_NET, SRC_ROU, SRC_VTYPES, SRC_KEEPALIVE):
        if not os.path.exists(p):
            sys.exit(f"missing mode-5 input: {p}")

    wanted = {int(x) for x in args.only.split(",") if x.strip()}
    points = [p for p in POINTS if not wanted or p[0] in wanted]

    build_routes()
    results = []
    for kmh, ms, mode in points:
        print(f"\n=== S-SOTA-2  v={kmh} km/h ({ms} m/s)  -> mobility_mode={mode} ===")
        net = build_net(kmh, ms)
        vtypes = build_vtypes(kmh, ms)
        fcd, tcl, tp = run_sumo(kmh, ms, net, vtypes, args.fcd_dir)
        results.append(validate(kmh, ms, fcd, tcl, tp))

    print("\n=== S-SOTA-2 summary ===")
    print(f"{'km/h':>5} {'nominal':>8} {'achieved':>9} {'%':>6} {'wu95':>6} "
          f"{'min_st':>7} {'end':>6} {'nodes':>6}")
    for r in results:
        print(f"{r['kmh']:>5} {r['nominal']:>8.2f} {r['achieved']:>9.2f} "
              f"{100*r['achieved']/r['nominal']:>5.1f}% {str(r['warmup95']):>6} "
              f"{r['min_steady']:>7} {r['tmax']:>6.1f} {r['nodes']:>6}")
    print("\nReport the ACHIEVED column alongside the nominal x-axis: the upper "
          "points saturate on klbb2km's 39.5 m median edge length.")
    print("\nRSU deployment is unchanged for all four points: "
          "../klbb2km_rsus_8x8.csv (64 RSUs).")


if __name__ == "__main__":
    main()
